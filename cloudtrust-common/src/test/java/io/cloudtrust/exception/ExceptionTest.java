package io.cloudtrust.exception;

import org.junit.Test;

import io.cloudtrust.tests.ExceptionVerifier;

public class ExceptionTest {
	@Test
	public void cloudtrustExceptionCoverage() {
		ExceptionVerifier.verify(CloudtrustException.class);
	}

	@Test
	public void cloudtrustRuntimeExceptionCoverage() {
		ExceptionVerifier.verify(CloudtrustRuntimeException.class);
	}
}
