package com.github.dbadia.sqrl.atmosphere;

import java.io.IOException;
import java.io.Reader;
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

import com.github.dbadia.sqrl.server.SqrlAuthStateMonitor;
import com.github.dbadia.sqrl.server.SqrlAuthenticationStatus;
import com.github.dbadia.sqrl.server.SqrlClientAuthStateUpdater;
import com.github.dbadia.sqrl.server.SqrlConfig;
import com.github.dbadia.sqrl.server.exception.SqrlInvalidDataException;
import com.github.dbadia.sqrl.server.util.SelfExpiringHashMap;
import com.github.dbadia.sqrl.server.util.SqrlSanitize;
import com.github.dbadia.sqrl.server.util.SqrlUtil;

@AtmosphereHandlerService(path = "/sqrlauthpolling", interceptors = { AtmosphereResourceLifecycleInterceptor.class })
public class AtmosphereClientAuthStateUpdater implements AtmosphereHandler, SqrlClientAuthStateUpdater {
	private static final int		JSON_SIZE_LIMIT		= 200;
	private static final Logger		logger				= LoggerFactory
			.getLogger(AtmosphereClientAuthStateUpdater.class);
	private static final String		JSON_TAG_NAME		= "state";

	/**
	 * Table of correlator cookie to most current AtmosphereResource request object. This is necessary as certain
	 * polling mechanisms, such as long polling can timeout and result in subsequent atmosphere requests. This ensures
	 * we send our reply to the current atmosphere connection instead of a stale one.
	 *
	 * We use {@link SelfExpiringHashMap} so that old entries get removed automatically. We keep this as a static as
	 * it's possible the atmosphere will create multiple instances of this class
	 */
	private static SelfExpiringHashMap<String, AtmosphereResource>			currentAtmosphereRequestTable;
	/**
	 * There is a subtle race condition with the atmosphere framework whereas the client needs to reconnect but this
	 * logic sends the status update to the old connection. As a workaround, we cache the latest state change here for a
	 * short amount of time
	 */
	private static SelfExpiringHashMap<String, SqrlAuthenticationStatus>	stateChangeCache;
	private static SqrlAuthStateMonitor										sqrlAuthStateMonitor		= null;
	private static String													sqrlCorrelatorCookieName	= null;

	@Override
	public void initSqrl(final SqrlConfig sqrlConfig, final SqrlAuthStateMonitor sqrlAuthStateMonitor) {
		if (currentAtmosphereRequestTable == null) {
			AtmosphereClientAuthStateUpdater.currentAtmosphereRequestTable = new SelfExpiringHashMap<>(
					sqrlConfig.getNutValidityInMillis());
		}
		if (stateChangeCache == null) {
			AtmosphereClientAuthStateUpdater.stateChangeCache = new SelfExpiringHashMap<>(
					TimeUnit.SECONDS.toMillis(20));
		}
		AtmosphereClientAuthStateUpdater.sqrlAuthStateMonitor = sqrlAuthStateMonitor;
		AtmosphereClientAuthStateUpdater.sqrlCorrelatorCookieName = sqrlConfig.getCorrelatorCookieName();
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
				// GETs are the browser polling for an update; suspend it until we are ready to respond
				if (logger.isInfoEnabled()) {
					logger.info("onRequest {} {} {} {} {}", request.getMethod(), correlatorId, resource.uuid(),
							SqrlUtil.cookiesToString(request.getCookies()), request.getHeader("User-Agent"));
				}
				final SqrlAuthenticationStatus newAuthStatus = stateChangeCache.remove(correlatorId);
				if (newAuthStatus == null) {
					resource.suspend();
					updateCurrentAtomosphereRequest(resource);
				} else {
					transmitResponseToResource(correlatorId, resource, newAuthStatus);
					logger.info("Immediate response triggered for polling request, sending {}", newAuthStatus);
				}
			} else if (request.getMethod().equalsIgnoreCase("POST")) {
				// Post means we're being sent data, should be trivial JSON: { "state" : "COMMUNICATING" }
				String browserStatusString = null;
				try (Reader reader = request.getReader()) {
					browserStatusString = validateAndParseStateValueFromJson(reader);
				}
				if (logger.isInfoEnabled()) {
					logger.info("onRequest {} {} {} {} {} {}", request.getMethod(), correlatorId,
							resource.uuid(), browserStatusString, SqrlUtil.cookiesToString(request.getCookies()),
							request.getHeader("User-Agent"));
				}

				SqrlAuthenticationStatus browserStatus = null;
				SqrlAuthenticationStatus newStatus = null;
				if (correlatorId == null) {
					logger.warn("Correaltor not found in browser polling request");
					newStatus = SqrlAuthenticationStatus.ERROR_BAD_REQUEST;
				}

				try {
					browserStatus = SqrlAuthenticationStatus.valueOf(browserStatusString);
					// Set them the same so, by default we will query the db
				} catch (final RuntimeException e) {
					logger.warn("Browser {} sent invalid status {}", correlatorId, browserStatusString);
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
		} catch (final Exception e) {
			// Trap all exceptions here because we don't know what will happen if they bubble up to the atmosphere
			// framework... it may kill an important thread or otherwise
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
		stateChangeCache.put(correlatorId, newAuthStatus);
		if (correlatorId == null) {
			logger.error("Cant transmit new authStatus of {} since correlator was null", newAuthStatus);
			return;
		}
		final AtmosphereResource resource = currentAtmosphereRequestTable.get(correlatorId);
		if (resource == null) {
			logger.error("AtmosphereResource not found for correlator {}, can't communicate status change from {} to {}",
					correlatorId, oldAuthStatus, newAuthStatus);
			return;
		}
		transmitResponseToResource(correlatorId, resource, newAuthStatus);
	}

	private void transmitResponseToResource(final String correlatorId, final AtmosphereResource resource,
			final SqrlAuthenticationStatus newAuthStatus) {
		final AtmosphereResponse response = resource.getResponse();
		try {
			response.getWriter().write(newAuthStatus.toString());
			switch (resource.transport()) {
				case JSONP:
				case LONG_POLLING:
					resource.resume();
					break;
				case WEBSOCKET:
					break;
				case SSE: // flush() is not in the original examples but is necessary for SSE
				case STREAMING:
					response.getWriter().flush();
					break;
				default:
					// This appears to be legit for some transports, just do a trace log
					logger.trace("No action taken to flush response for transport {} for correaltor {}",
							resource.transport(), correlatorId);
			}
			if (newAuthStatus == SqrlAuthenticationStatus.AUTH_COMPLETE) {
				// The browser received the complete update and is redirecting, clean up
				sqrlAuthStateMonitor.stopMonitoringCorrelator(correlatorId);
			}
		} catch (final Exception e) {
			logger.error(new StringBuilder("Caught IO error trying to send status of ").append(newAuthStatus)
					.append(" via atmosphere to correaltor ").append(correlatorId)
					.append(" with transport ").append(resource.transport()).toString(), e);
		}
	}

	/**
	 * Certain atmosphere polling mechanisms (long polling, etc) can time out and result in subsequent polling requests.
	 * This method must be called each time a new request is received so we can send our response to the most current
	 * resource object
	 *
	 * @param resource
	 *            the atmosphere resource that was received
	 */
	public void updateCurrentAtomosphereRequest(final AtmosphereResource resource) {
		final String correaltorId = extractCorrelatorFromCookie(resource);
		if (logger.isTraceEnabled()) {
			logger.trace("In updateCurrentAtomosphereRequest for correaltorId {}, update? {}",
					correaltorId, currentAtmosphereRequestTable.containsKey(correaltorId));
		}
		currentAtmosphereRequestTable.put(correaltorId, resource);
	}

	@Override
	public void onStateChange(final AtmosphereResourceEvent event) throws IOException {
		final AtmosphereResource resource = event.getResource();
		if (!event.isResuming()) {
			// Connection is closed
			logger.info("Atmosphere browser closed connection for correaltor {}, uuid {}",
					extractCorrelatorFromCookie(resource), resource.uuid());
		}
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

	// package-protected for unit testing
	static String validateAndParseStateValueFromJson(final Reader reader) throws SqrlInvalidDataException, IOException {
		final char[] chars = new char[JSON_SIZE_LIMIT+1];
		if(reader.read(chars) > JSON_SIZE_LIMIT) {
			throw new SqrlInvalidDataException("Atomsophere json exeeded max size of " + JSON_SIZE_LIMIT);
		}
		String shouldBeJson = new String(chars);
		// Our json is trivial, just parse using index of instead of pulling in a json lib
		shouldBeJson = shouldBeJson.trim();
		if(!shouldBeJson.startsWith("{") || !shouldBeJson.endsWith("}")) {
			throw new SqrlInvalidDataException("Atomsophere json was invalid: " + shouldBeJson);
		}
		shouldBeJson = shouldBeJson.replace("{", "");
		shouldBeJson = shouldBeJson.replace("}", "");
		shouldBeJson = shouldBeJson.replace("\"", "");
		shouldBeJson = shouldBeJson.trim();
		final int colonIndex = shouldBeJson.lastIndexOf(':');
		if(colonIndex == -1) {
			throw new SqrlInvalidDataException("Atomsophere json was missing colon: " + shouldBeJson);
		}
		final String[] partArray = shouldBeJson.split(":");
		// Add tokens should be alphanumeric
		for (int i = 0; i < partArray.length; i++) {
			partArray[i] = partArray[i].trim();
			SqrlSanitize.inspectIncomingSqrlData(partArray[i]);
		}
		if (partArray.length != 2) {
			throw new SqrlInvalidDataException("Atomsophere json had wrong number of parts: " + shouldBeJson);
		} else if (!JSON_TAG_NAME.equals(partArray[0].trim())) {
			throw new SqrlInvalidDataException("Atomsophere json was missing expected tag name: " + shouldBeJson);
		}
		return partArray[1];
	}

	// package-protected for unit testing
	static String extractCorrelatorFromCookie(final AtmosphereResource resource) {
		if (resource.getRequest() == null) {
			logger.error("Couldn't extract correlator from cookie since atmosphere request was null");
			return null;
		}
		if (resource.getRequest().getCookies() == null) {
			logger.error("Couldn't extract correlator from cookie since atmosphere request.getCookies() was null");
			return null;
		}

		for (final Cookie cookie : resource.getRequest().getCookies()) {
			if (sqrlCorrelatorCookieName.equals(cookie.getName())) {
				final String value = cookie.getValue();
				try {
					SqrlSanitize.inspectIncomingSqrlData(value);
					return value;
				} catch (final SqrlInvalidDataException e) {
					logger.error("Correlator cookie found but failed data validation: {}", value);
					return null;
				}
			}
		}
		logger.error("Couldn't extract correlator from cookie; cookie not found in atmosphere request.getCookies()");
		return null;
	}

}
