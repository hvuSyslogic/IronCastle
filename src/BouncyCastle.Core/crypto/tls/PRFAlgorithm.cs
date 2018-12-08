﻿namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 5246
	/// <para>
	/// Note that the values here are implementation-specific and arbitrary. It is recommended not to
	/// depend on the particular values (e.g. serialization).
	/// </para>
	/// </summary>
	public class PRFAlgorithm
	{
		/*
		 * Placeholder to refer to the legacy TLS algorithm
		 */
		public const int tls_prf_legacy = 0;

		public const int tls_prf_sha256 = 1;

		/*
		 * Implied by RFC 5288
		 */
		public const int tls_prf_sha384 = 2;
	}

}