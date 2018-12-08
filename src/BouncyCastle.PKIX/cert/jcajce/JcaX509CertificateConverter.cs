using System;

namespace org.bouncycastle.cert.jcajce
{

	/// <summary>
	/// Converter for producing X509Certificate objects tied to a specific provider from X509CertificateHolder objects.
	/// </summary>
	public class JcaX509CertificateConverter
	{
		private CertHelper helper = new DefaultCertHelper();

		/// <summary>
		/// Base constructor, configure with the default provider.
		/// </summary>
		public JcaX509CertificateConverter()
		{
			this.helper = new DefaultCertHelper();
		}

		/// <summary>
		/// Set the provider to use from a Provider object.
		/// </summary>
		/// <param name="provider"> the provider to use. </param>
		/// <returns> the converter instance. </returns>
		public virtual JcaX509CertificateConverter setProvider(Provider provider)
		{
			this.helper = new ProviderCertHelper(provider);

			return this;
		}

		/// <summary>
		/// Set the provider to use by name.
		/// </summary>
		/// <param name="providerName"> name of the provider to use. </param>
		/// <returns> the converter instance. </returns>
		public virtual JcaX509CertificateConverter setProvider(string providerName)
		{
			this.helper = new NamedCertHelper(providerName);

			return this;
		}

		/// <summary>
		/// Use the configured converter to produce a X509Certificate object from a X509CertificateHolder object.
		/// </summary>
		/// <param name="certHolder">  the holder to be converted </param>
		/// <returns> a X509Certificate object </returns>
		/// <exception cref="CertificateException"> if the conversion is unable to be made. </exception>
		public virtual X509Certificate getCertificate(X509CertificateHolder certHolder)
		{
			try
			{
				CertificateFactory cFact = helper.getCertificateFactory("X.509");

				return (X509Certificate)cFact.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
			}
			catch (IOException e)
			{
				throw new ExCertificateParsingException(this, "exception parsing certificate: " + e.Message, e);
			}
			catch (NoSuchProviderException e)
			{
				throw new ExCertificateException(this, "cannot find required provider:" + e.Message, e);
			}
		}

		public class ExCertificateParsingException : CertificateParsingException
		{
			private readonly JcaX509CertificateConverter outerInstance;

			internal Exception cause;

			public ExCertificateParsingException(JcaX509CertificateConverter outerInstance, string msg, Exception cause) : base(msg)
			{
				this.outerInstance = outerInstance;

				this.cause = cause;
			}

			public virtual Exception getCause()
			{
				return cause;
			}
		}

		public class ExCertificateException : CertificateException
		{
			private readonly JcaX509CertificateConverter outerInstance;

			internal Exception cause;

			public ExCertificateException(JcaX509CertificateConverter outerInstance, string msg, Exception cause) : base(msg)
			{
				this.outerInstance = outerInstance;

				this.cause = cause;
			}

			public virtual Exception getCause()
			{
				return cause;
			}
		}
	}
}