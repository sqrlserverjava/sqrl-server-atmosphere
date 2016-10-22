package com.github.dbadia.sqrl.atmosphere;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.Cookie;

import org.atmosphere.config.service.AtmosphereHandlerService;
import org.atmosphere.cpr.AtmosphereHandler;
import org.atmosphere.cpr.AtmosphereRequest;
import org.atmosphere.cpr.AtmosphereResource;
import org.atmosphere.cpr.AtmosphereResourceEvent;
import org.atmosphere.cpr.AtmosphereResponse;
import org.atmosphere.interceptor.AtmosphereResourceLifecycleInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.dbadia.sqrl.server.ClientAuthStateUpdater;
import com.github.dbadia.sqrl.server.SqrlAuthStateMonitor;
import com.github.dbadia.sqrl.server.SqrlAuthenticationStatus;
import com.github.dbadia.sqrl.server.SqrlConfig;
import com.github.dbadia.sqrl.server.util.SelfExpiringHashMap;

// TODO: rename /sqrlauthpolling
@AtmosphereHandlerService(path = "/sqrlauthwebsocket", interceptors = { AtmosphereResourceLifecycleInterceptor.class })
public class AtmosphereClientAuthStateUpdater implements AtmosphereHandler, ClientAuthStateUpdater {
	private static final Logger logger = LoggerFactory.getLogger(AtmosphereClientAuthStateUpdater.class);

	/**
	 * Table of correlator cookie to most current AtmosphereResource request object. This is necessary as certain
	 * polling mechanisms, such as long polling can timeout and result in subsequent atmosphere requests. This ensures
	 * we send our reply to the current atmosphere connection instead of a stale one.
	 *
	 * We use {@link SelfExpiringHashMap} so that old entries get removed automatically. We keep this as a static as
	 * it's possible the atmosphere will create multiple instances of this class
	 */
	private static SelfExpiringHashMap<String, AtmosphereResource> currentAtmosphereRequestTable;
	private static SqrlAuthStateMonitor sqrlAuthStateMonitor = null;
	private static String sqrlCookieName = null; // TODO: reame to sqrlCorrelatorCookieName

	@Override
	public void initSqrl(final SqrlConfig sqrlConfig, final SqrlAuthStateMonitor sqrlAuthStateMonitor) {
		if (currentAtmosphereRequestTable == null) {
			final long millisToExpire = TimeUnit.MINUTES.toMillis(sqrlConfig.getNutValidityInSeconds());
			AtmosphereClientAuthStateUpdater.currentAtmosphereRequestTable = new SelfExpiringHashMap<>(millisToExpire);
		}
		this.sqrlAuthStateMonitor = sqrlAuthStateMonitor;
		this.sqrlCookieName = sqrlConfig.getCorrelatorCookieName();
	}

	/**
	 * Atmosphere method that is trigger when the browser sends us a request Our convention is such that GET requests
	 * are polling requests; POST requests provide us with data
	 */
	@Override
	public void onRequest(final AtmosphereResource resource) {
		String correlatorId = null;
		try {
			final AtmosphereRequest request = resource.getRequest();
			correlatorId = extractCorrelatorFromCookie(resource);

			if (request.getMethod().equalsIgnoreCase("GET")) {
				// GET is a polling request; suspend it until we are ready to respond
				if (logger.isInfoEnabled()) {
					logger.info("onRequest {} {} {} {} {}", request.getMethod(), correlatorId, resource.uuid(),
							toString(request.getCookies()), request.getHeader("User-Agent"));
				}
				// TODO: handle the case where the client retries
				// sqrlAuthStateMonitor.getCurrentStateForSessionId(atmosphereSessionId);
				resource.suspend();
				updateCurrentAtomosphereRequest(resource);
			} else if (request.getMethod().equalsIgnoreCase("POST")) {
				// Post means we're being sent data
				final String message = request.getReader().readLine().trim(); // TODO: no trim and better parser
				if (logger.isInfoEnabled()) {
					logger.info("onRequest {} {} {} {} {} {}", request.getMethod(), correlatorId,
							resource.uuid(), message, toString(request.getCookies()),
							request.getHeader("User-Agent"));
				}
				// Simple JSON message { "correlator" : "XYZ", "status" : "CORRELATOR_ISSUED" }
				final String correlatorMessageString = message.substring(message.indexOf(':') + 2,
						message.indexOf(',') - 1);
				if (!correlatorMessageString.equals(correlatorId)) {
					logger.error("Mismatch between atomsphere correlator param and cookie");
				}
				final String browserStatusString = message.substring(message.lastIndexOf(':') + 2, message.length() - 2);

				if ("redirect".equals(browserStatusString)) {
					// The browser received the complete update and is redirecting, clean up
					sqrlAuthStateMonitor.stopMonitoringCorrelator(correlatorId);
				} else {
					SqrlAuthenticationStatus browserStatus = null;
					SqrlAuthenticationStatus newStatus = null;
					if (correlatorId == null) {
						logger.warn("Browser {} sent null correlator {}", correlatorId, message);
						newStatus = SqrlAuthenticationStatus.ERROR_BAD_REQUEST;
					}

					try {
						browserStatus = SqrlAuthenticationStatus.valueOf(browserStatusString);
						// Set them the same so, by default we will query the db
					} catch (final RuntimeException e) {
						logger.warn("Browser {} sent invalid status {}", correlatorId, message);
						newStatus = SqrlAuthenticationStatus.ERROR_BAD_REQUEST;
					}
					if (newStatus != null) {
						// Error state, send the reply right away
						pushStatusUpdateToBrowser(correlatorId, browserStatus, newStatus);
					} else if (sqrlAuthStateMonitor == null) {
						logger.error("init error, sqrlAuthStateMonitor is null, can't monitor correlator for change");
					} else {
						// Let the monitor watch the db for correlator change, then send the reply when it changes
						sqrlAuthStateMonitor.monitorCorrelatorForChange(correlatorId, browserStatus);
					}
				}
			}
		} catch (final Exception e) {
			// Trap all exceptions here because we don't know what will happen if they bubble up to the atmosphere
			// framework
			logger.error(new StringBuilder("Error processing atmosphere request for correlator=")
					.append(correlatorId).toString(), e);
		}
	}

	/**
	 * Invoked by {@link SqrlAuthStateMonitor} when it is time to respond to a browsers polling request with an update
	 */
	@Override
	public void pushStatusUpdateToBrowser(final String correlatorId,
			final SqrlAuthenticationStatus oldAuthStatus, final SqrlAuthenticationStatus newAuthStatus) {
		final AtmosphereResource resource = currentAtmosphereRequestTable.get(correlatorId);
		if (resource == null) {
			logger.error("AtmosphereResource not found for correlator {}, can't communicate status change from {} to {}",
					correlatorId, oldAuthStatus, newAuthStatus);
			return;
		}
		final AtmosphereResponse response = resource.getResponse();
		logger.info("Sending atmosphere state change from {} to  {} via {} to {}, ", oldAuthStatus, newAuthStatus,
				resource.transport(), correlatorId);
		try {
			response.getWriter().write(newAuthStatus.toString());
			switch (resource.transport()) {
				case JSONP:
				case LONG_POLLING:
					resource.resume();
					break;
				case WEBSOCKET:
					break;
				case SSE: // this is not in the original examples but is necessary for SSE
				case STREAMING:
					response.getWriter().flush();
					break;
				default:
					// This appears to be legit for some transports, just do a debug log
					logger.debug("No action taken to flush response for transport {} for correaltor {}",
							resource.transport(), correlatorId);
			}
		} catch (final Exception e) {
			logger.error(new StringBuilder("Caught IO error trying to send status of ").append(newAuthStatus)
					.append(" via atmosphere to correaltor ").append(correlatorId)
					.append(" with transport ").append(resource.transport()).toString(), e);
		}
	}

	/**
	 * Certain atmosphere polling mechanisms (long polling, etc)timeout and result in subsequent polling requests. This
	 * method must be called each time a new request is received so we can send our response to the current, valid
	 * resource object
	 *
	 * @param resource
	 *            the atmosphere resource that was received
	 */
	public void updateCurrentAtomosphereRequest(final AtmosphereResource resource) {
		final String atmosphereSessionId = extractCorrelatorFromCookie(resource); // TODO: rename to correaltorId
		if (logger.isDebugEnabled()) {
			logger.debug("In updateCurrentAtomosphereRequest for atmosphereSessionId {}, update? {}",
					atmosphereSessionId, currentAtmosphereRequestTable.containsKey(atmosphereSessionId));
		}
		currentAtmosphereRequestTable.put(atmosphereSessionId, resource);
	}

	@Override
	public void onStateChange(final AtmosphereResourceEvent event) throws IOException {
		final AtmosphereResource resource = event.getResource();
		if (!event.isResuming()) {
			// There's no way to log the session id since the connection is closed
			// If we try we get IllegalStateException: Cannot create a session after the response has been committed
			logger.info("Atmosphere browser closed connection for uuid {}", resource.uuid());
		}
	}

	private static String extractCorrelatorFromCookie(final AtmosphereResource resource) {
		if (resource.getRequest() == null) {
			logger.error("Couldn't extract correlator from cookie since atmosphere request was null");
			return null;
		}
		if (resource.getRequest().getCookies() == null) {
			logger.error("Couldn't extract correlator from cookie since atmosphere request.getCookies() was null");
			return null;
		}

		for (final Cookie cookie : resource.getRequest().getCookies()) {
			if (sqrlCookieName.equals(cookie.getName())) {
				return cookie.getValue();
			}
		}
		logger.error("Couldn't extract correlator from cookie; cookie not found in atmosphere request.getCookies()");
		return null;
	}

	public void onDisconnect(final AtmosphereResponse response) throws IOException {
		final AtmosphereResourceEvent event = response.resource().getAtmosphereResourceEvent();
		final String correlatorId = extractCorrelatorFromCookie(response.resource());
		if (event.isCancelled()) {
			logger.info("Browser {} unexpectedly disconnected", correlatorId);
		} else if (event.isClosedByClient()) {
			logger.info("Browser {} closed the connection", correlatorId);
		}
	}

	@Override
	public void destroy() {
		// Nothing to do
	}

	private static final String toString(final Cookie[] cookieArray) {
		final StringBuilder buf = new StringBuilder("C[ ");
		for (final Cookie cookie : cookieArray) {
			buf.append(cookie.getName()).append("=").append(cookie.getValue()).append(", ");
		}

		return buf.substring(0, buf.length() - 2) + " ]";
	}
}
