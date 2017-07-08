package com.github.sqrlserverjava.atmosphere;

import java.io.StringReader;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import junit.framework.TestCase;

@RunWith(Parameterized.class)
public class AtmosphereClientSanitizeTest {

	@Parameters(name = "{index}: expectedString={0}, data={1}")
	public static Collection<Object[]> data() {
		// @formatter:off
		// expectedString: null means exception should be thrown
		return Arrays.asList(new Object[][] {
			{ "AUTH_COMPLETE", "{ \"state\": \"AUTH_COMPLETE\" }" },
			// It doesn't validate the string
			{ "BLAH", "{ \"state\": \"BLAH\" }" },
			{ null, "{ ! \"state\": \"BLAH\" }" },
			{ null, " \"state\": \"BLAH\" }" },
			{ null, "{ \"state\": \"BLAH\" " },
			{ null, "{ \"state\" \"BLAH\" }" },
		});
		// @formatter:on
	}

	@Test
	public void testIt() throws Exception {
		try (StringReader reader = new StringReader(json)) {
			AtmosphereClientAuthStateUpdater.validateAndParseStateValueFromJson(reader);
			TestCase.assertNotNull("Exception was expected, but none was thrown", expected);
		} catch (final Exception e) {
			if (expected != null) {
				// Wasn't expected, just throw it
				throw e;
			}
		}
	}

	/**
	 * expected, null means exception should be thrown
	 */
	@Parameter(value = 0)
	public /* NOT private */ String expected;

	@Parameter(value = 1)
	public /* NOT private */ String json;
}
