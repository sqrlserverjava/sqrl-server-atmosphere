package com.github.sqrlserverjava.atmosphere;

import org.junit.Test;
import org.mockito.Mockito;

import com.github.sqrlserverjava.SqrlAuthStateMonitor;
import com.github.sqrlserverjava.SqrlConfig;
import com.github.sqrlserverjava.SqrlServerOperations;

public class AtmosphereClientAuthStateUpdaterTest {

	@Test
	public void testInit() throws Throwable {
		final SqrlConfig sqrlConfig = new SqrlConfig();
		final SqrlAuthStateMonitor mockAuthStateMonitor = Mockito.mock(SqrlAuthStateMonitor.class);
		final AtmosphereClientAuthStateUpdater updater = new AtmosphereClientAuthStateUpdater();
		final SqrlServerOperations operations = Mockito.mock(SqrlServerOperations.class);
		updater.initSqrl(operations, sqrlConfig, mockAuthStateMonitor);
	}

}
