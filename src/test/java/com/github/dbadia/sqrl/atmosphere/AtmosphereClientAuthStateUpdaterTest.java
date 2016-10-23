package com.github.dbadia.sqrl.atmosphere;

import org.junit.Test;
import org.mockito.Mockito;

import com.github.dbadia.sqrl.server.SqrlAuthStateMonitor;
import com.github.dbadia.sqrl.server.SqrlConfig;

public class AtmosphereClientAuthStateUpdaterTest {

	@Test
	public void testInit() throws Throwable {
		final SqrlConfig sqrlConfig = new SqrlConfig();
		final SqrlAuthStateMonitor mockAuthStateMonitor = Mockito.mock(SqrlAuthStateMonitor.class);
		final AtmosphereClientAuthStateUpdater updater = new AtmosphereClientAuthStateUpdater();
		updater.initSqrl(sqrlConfig, mockAuthStateMonitor);
	}

}
