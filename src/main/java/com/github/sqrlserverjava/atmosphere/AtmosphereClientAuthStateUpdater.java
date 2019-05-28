package com.github.sqrlserverjava.atmosphere;

import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.buildParamArrayForLogging;
import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.cleanup;
import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.formatForLogging;
import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.initLogging;
import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.putData;
import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.Channel.POLL;
import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.LogField.COR;
import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.LogField.POLL_BROWSER_STATE;
import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.LogField.POLL_TRANSPORT;
import static com.github.sqrlserverjava.backchannel.SqrlClientRequestLoggingUtil.LogField.POLL_UUID;
import static com.github.sqrlserverjava.enums.SqrlAuthenticationStatus.AUTHENTICATED_BROWSER;
import static com.github.sqrlserverjava.enums.SqrlAuthenticationStatus.AUTHENTICATED_CPS;
import static com.github.sqrlserverjava.enums.SqrlAuthenticationStatus.ERROR_BAD_REQUEST;

import java.io.IOException;
import java.io.Reader;
import java.util.concurrent.TimeUnit;

import org.atmosphere.config.service.AtmosphereHandlerService;
import org.atmosphere.cpr.AtmosphereHandler;
import org.atmosphere.cpr.AtmosphereRequest;
import org.atmosphere.cpr.AtmosphereResource;
import org.atmosphere.cpr.AtmosphereResourceEvent;
import org.atmosphere.cpr.AtmosphereResponse;
import org.atmosphere.interceptor.AtmosphereResourceLifecycleInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import com.eclipsesource.json.ParseException;
import com.github.sqrlserverjava.SqrlAuthStateMonitor;
import com.github.sqrlserverjava.SqrlClientAuthStateUpdater;
import com.github.sqrlserverjava.SqrlConfig;
import com.github.sqrlserverjava.SqrlServerOperations;
import com.github.sqrlserverjava.enums.SqrlAuthenticationStatus;
import com.github.sqrlserverjava.exception.SqrlInvalidDataException;
import com.github.sqrlserverjava.util.SelfExpiringHashMap;
import com.github.sqrlserverjava.util.VersionExtractor;
import com.github.sqrlserverjava.util.VersionExtractor.Module;
@AtmosphereHandlerService(path = "/sqrlauthpolling", interceptors = { AtmosphereResourceLifecycleInterceptor.class })
public class AtmosphereClientAuthStateUpdater implements AtmosphereHandler, SqrlClientAuthStateUpdater {
	private static final int JSON_SIZE_LIMIT = 300;
	private static final Logger logger = LoggerFactory.getLogger(AtmosphereClientAuthStateUpdater.class);

	/**
	 * Table of correlator cookie to most current AtmosphereResource request object. This is necessary as certain
	 * polling mechanisms, such as long polling can timeout and result in subsequent atmosphere requests. This ensures
	 * we send our reply to the current atmosphere connection instead of a stale one.
	 *
	 * We use {@link SelfExpiringHashMap} so that old entries get removed automatically. We keep this as a static as
	 * it's possible the atmosphere will create multiple instances of this class
	 */
	private static volatile SelfExpiringHashMap<String, AtmosphereResource> currentAtmosphereRequestTable; // TODO:
	// rename to
	// ResourceTable
	/**
	 * There is a subtle race condition with the atmosphere framework whereas the client needs to reconnect but this
	 * logic sends the status update to the old connection. As a workaround, we cache the latest state change here for a
	 * short amount of time
	 */
	private static volatile SelfExpiringHashMap<String, SqrlAuthenticationStatus> stateChangeCache;
	private static SqrlAuthStateMonitor sqrlAuthStateMonitor = null;
	private static SqrlServerOperations sqrlServerOperations = null;

	@Override
	public void initSqrl(final SqrlServerOperations sqrlServerOperations, final SqrlConfig sqrlConfig,
			final SqrlAuthStateMonitor sqrlAuthStateMonitor) {
		logger.info(VersionExtractor.extractDetailedBuildInfo(Module.ATMOSPHERE));
		if (currentAtmosphereRequestTable == null) {
			AtmosphereClientAuthStateUpdater.currentAtmosphereRequestTable = new SelfExpiringHashMap<>(
					sqrlConfig.getNutValidityInMillis());
		}
		if (stateChangeCache == null) {
			AtmosphereClientAuthStateUpdater.stateChangeCache = new SelfExpiringHashMap<>(
					TimeUnit.SECONDS.toMillis(20));
		}
		AtmosphereClientAuthStateUpdater.sqrlAuthStateMonitor = sqrlAuthStateMonitor;
		AtmosphereClientAuthStateUpdater.sqrlServerOperations = sqrlServerOperations;
	}

	// TODO: validate header sizes, throw ex if too big
	/**
	 * Atmosphere method that is trigger when the browser sends us a request Our convention is such that GET requests
	 * are polling requests; POST requests provide us with data
	 */
	@Override
	public void onRequest(final AtmosphereResource resource) {
		String correlator = null; // Only set/known during post
		final String atmosUuid = resource.uuid();
		try {
			final AtmosphereRequest request = resource.getRequest();
			String browserStateString = null;
			final String loggingProcess = "atmos"+request.getMethod().toLowerCase();
			initLogging(POLL, loggingProcess, request);
			if (request.getMethod().equalsIgnoreCase("GET")) {
				correlator = request.getHeader("X-sqrl-corelator");
			} else if(request.getMethod().equalsIgnoreCase("POST")) {
				try (Reader reader = request.getReader()) {
					final JsonObject jsonObject = validateAndParseStateValueFromJson(correlator, reader);
					correlator = jsonObject.get("correlator").asString();
					browserStateString = jsonObject.get("state").asString();
					putData(POLL_BROWSER_STATE, browserStateString);
				}
			}
			putData(POLL_UUID, atmosUuid, POLL_TRANSPORT, resource.transport(), COR, correlator);

			logger.debug(formatForLogging("Processing atmosphere request with params: {}"),
					buildParamArrayForLogging(request));
			if (request.getMethod().equalsIgnoreCase("GET")) {
				// GETs are the browser polling for an update; suspend it until we are ready to respond
				// This is the one place where we don't have access to the correlator
				resource.suspend();
				final SqrlAuthenticationStatus newAuthStatus = stateChangeCache.get(correlator);
				if (newAuthStatus == null) {
					resource.suspend();
					updateCurrentAtomosphereRequest(correlator, resource, request.getHeader("User-Agent"));
				} else {
					transmitResponseToResource(correlator, resource, newAuthStatus);
					logger.info(formatForLogging("Immediate response triggered for polling request, sending {}"),
							newAuthStatus);
				}
			} else if (request.getMethod().equalsIgnoreCase("POST")) {
				// Post means we're being sent data, should be trivial JSON: { "state" : "COMMUNICATING" }
				updateCurrentAtomosphereRequest(correlator, resource, request.getHeader("User-Agent"));
				final SqrlAuthenticationStatus newAuthStatus = stateChangeCache.get(correlator);
				logger.info("newAuthStatus={}", newAuthStatus);
				if (newAuthStatus != null) {
					transmitResponseToResource(correlator, resource, newAuthStatus);
					logger.info(formatForLogging("Immediate response triggered for polling request, sending {}"),
							newAuthStatus);
				}

				SqrlAuthenticationStatus browserState = null;
				SqrlAuthenticationStatus newStatus = null;

				try {
					browserState = SqrlAuthenticationStatus.valueOf(browserStateString);
					// Set them the same so, by default we will query the db TOOD: what?
				} catch (final RuntimeException e) {
					logger.warn(formatForLogging("browser sent invalid state"));
					newStatus = ERROR_BAD_REQUEST;
				}

				if (newStatus != null) {
					// Error state, send the reply right away
					pushStatusUpdateToBrowser(correlator, browserState, newStatus);
				} else if (sqrlAuthStateMonitor == null) {
					logger.error(formatForLogging(
							"init error, sqrlAuthStateMonitor is null, can't monitor correlator for change"));
				} else if (browserState == AUTHENTICATED_CPS) {
					// State of CPS means we no longer need to monitor and should clear all cookies
					sqrlServerOperations.browserFacingOperations().deleteSqrlAuthCookies(request,
							resource.getResponse());
					sqrlAuthStateMonitor.stopMonitoringCorrelator(correlator);
				} else {
					// Let the monitor watch the db for correlator change, then send the reply when it changes
					logger.debug(formatForLogging("triggering monitorCorrelatorForChange"));
					sqrlAuthStateMonitor.monitorCorrelatorForChange(correlator, browserState);
				}
			}
		} catch (final Exception e) {
			// Trap all exceptions here because we don't know what will happen if they bubble up to the atmosphere
			// framework... it may kill an important thread or otherwise
			logger.error(formatForLogging("Error processing atmosphere request"), e);
		} finally {
			cleanup();
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
			logger.error(formatForLogging("Cant transmit new authStatus of {} since correlator was null"),
					newAuthStatus);
			return;
		}
		final AtmosphereResource resource = currentAtmosphereRequestTable.get(correlatorId);
		if (resource == null) {
			logger.error(formatForLogging(
					"AtmosphereResource not found for correlator, can't communicate status change from {} to {}"),
					oldAuthStatus, newAuthStatus);
			return;
		}
		transmitResponseToResource(correlatorId, resource, newAuthStatus);
	}

	private void transmitResponseToResource(final String correlatorId, final AtmosphereResource resource,
			final SqrlAuthenticationStatus newAuthStatus) {
		final AtmosphereResponse response = resource.getResponse();
		try {
			response.setContentType("application/json");
			response.getWriter().write("{ \"status\":\"" + newAuthStatus.toString() + "\" }");// TODO: optimize
			switch (resource.transport()) {
			case JSONP:
			case LONG_POLLING:
			case POLLING: // TODO: is this right?
				logger.debug(formatForLogging("trying resource.resume() for POLLING"));
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
				logger.trace(formatForLogging("No action taken to flush response"));
			}
			if (newAuthStatus == AUTHENTICATED_BROWSER) {
				// The browser received the complete update and is redirecting, clean up
				sqrlAuthStateMonitor.stopMonitoringCorrelator(correlatorId);
			}
		} catch (final Exception e) {
			logger.error(formatForLogging("Caught IO error trying to send status of {}"), newAuthStatus, e);
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
	public void updateCurrentAtomosphereRequest(final String correaltorId, final AtmosphereResource resource,
			final String userAgent) { // TODO:
		// Resource
		final AtmosphereResource oldResource = currentAtmosphereRequestTable.put(correaltorId, resource);
		if (oldResource != null) {
			// This means the atmosphere client connection was destroyed and then reconnected
			// This is normal with some browsers even when connectivity is stable.
			// We rely on the correlator to co-ordinate front and back channel to correctly handle this case
			logger.info(formatForLogging("browser polling reconnected"));
		}
	}

	@Override
	public void onStateChange(final AtmosphereResourceEvent event) throws IOException {
		initLogging(POLL, "atmosStateChange", event.getResource().getRequest());
		if (!event.isResuming()) {
			// Connection is closed
			logger.debug(formatForLogging("browser closed connection"));
		}
	}

	// public void onDisconnect(final AtmosphereResponse response) throws IOException {
	// final AtmosphereResourceEvent event = response.resource().getAtmosphereResourceEvent();
	// final String correlatorId = extractCorrelatorFromCookie(response.resource());
	// if (event.isCancelled()) {
	// logger.info("Browser {} unexpectedly disconnected", correlatorId);
	// } else if (event.isClosedByClient()) {
	// logger.info("Browser {} closed the connection", correlatorId);
	// }
	// }

	@Override
	public void destroy() {
		// Nothing to do
	}

	// package-protected for unit testing
	static JsonObject validateAndParseStateValueFromJson(final String correlator, final Reader reader)
			throws SqrlInvalidDataException, IOException {
		final char[] chars = new char[JSON_SIZE_LIMIT+1];
		if (reader.read(chars) > JSON_SIZE_LIMIT) {
			throw new SqrlInvalidDataException("Atomsophere json exeeded max size of " + JSON_SIZE_LIMIT);
		}

		final String shouldBeJson = new String(chars).trim();
		try {
			final JsonObject jsonObject = Json.parse(shouldBeJson).asObject();
			if (jsonObject.get("state") == null || jsonObject.get("correlator") == null) {
				throw new SqrlInvalidDataException("Atomsophere json was invalid json=", shouldBeJson);
			}
			return jsonObject;
		} catch (final ParseException e) {
			throw new SqrlInvalidDataException("Error parsing atmosphere json.  json=", shouldBeJson);
		}
	}

}
