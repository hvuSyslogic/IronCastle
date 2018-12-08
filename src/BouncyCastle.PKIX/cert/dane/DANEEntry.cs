namespace org.bouncycastle.cert.dane
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Carrier class for a DANE entry.
	/// </summary>
	public class DANEEntry
	{
		public const int CERT_USAGE_CA = 0;
		public const int CERT_USAGE_PKIX_VALIDATE = 1;
		public const int CERT_USAGE_TRUST_ANCHOR = 2;
		public const int CERT_USAGE_ACCEPT = 3;

		internal const int CERT_USAGE = 0;
		internal const int SELECTOR = 1;
		internal const int MATCHING_TYPE = 2;

		private readonly string domainName;
		private readonly byte[] flags;
		private readonly X509CertificateHolder certHolder;

		public DANEEntry(string domainName, byte[] flags, X509CertificateHolder certHolder)
		{
			this.flags = flags;
			this.domainName = domainName;
			this.certHolder = certHolder;
		}

		public DANEEntry(string domainName, byte[] data) : this(domainName, Arrays.copyOfRange(data, 0, 3), new X509CertificateHolder(Arrays.copyOfRange(data, 3, data.Length)))
		{
		}

		public virtual byte[] getFlags()
		{
			return Arrays.clone(flags);
		}

		/// <summary>
		/// Return the certificate associated with this entry.
		/// </summary>
		/// <returns> the entry's certificate. </returns>
		public virtual X509CertificateHolder getCertificate()
		{
			return certHolder;
		}

		public virtual string getDomainName()
		{
			return domainName;
		}

		/// <summary>
		/// Return the full data string as it would appear in the DNS record - flags + encoding
		/// </summary>
		/// <returns> byte array representing the full data string. </returns>
		/// <exception cref="IOException"> if there is an issue encoding the certificate inside this entry. </exception>
		public virtual byte[] getRDATA()
		{
			byte[] certEnc = certHolder.getEncoded();
			byte[] data = new byte[flags.Length + certEnc.Length];

			JavaSystem.arraycopy(flags, 0, data, 0, flags.Length);
			JavaSystem.arraycopy(certEnc, 0, data, flags.Length, certEnc.Length);

			return data;
		}

		/// <summary>
		/// Return true if the byte string has the correct flag bytes to indicate a certificate entry.
		/// </summary>
		/// <param name="data"> the byte string of interest. </param>
		/// <returns> true if flags indicate a valid certificate, false otherwise. </returns>
		public static bool isValidCertificate(byte[] data)
		{
			// TODO: perhaps validate ASN.1 data as well...
			return ((data[CERT_USAGE] >= 0 || data[CERT_USAGE] <= 3) && data[SELECTOR] == 0 && data[MATCHING_TYPE] == 0);
		}
	}

}