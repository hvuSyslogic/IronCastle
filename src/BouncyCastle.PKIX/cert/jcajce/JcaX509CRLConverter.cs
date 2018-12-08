using System;

namespace org.bouncycastle.cert.jcajce
{

	/// <summary>
	/// Class for converting an X509CRLHolder into a corresponding X509CRL object tied to a
	/// particular JCA provider.
	/// </summary>
	public class JcaX509CRLConverter
	{
		private CertHelper helper = new DefaultCertHelper();

		/// <summary>
		/// Base constructor, configure with the default provider.
		/// </summary>
		public JcaX509CRLConverter()
		{
			this.helper = new DefaultCertHelper();
		}

		/// <summary>
		/// Set the provider to use from a Provider object.
		/// </summary>
		/// <param name="provider"> the provider to use. </param>
		/// <returns> the converter instance. </returns>
		public virtual JcaX509CRLConverter setProvider(Provider provider)
		{
			this.helper = new ProviderCertHelper(provider);

			return this;
		}

		/// <summary>
		/// Set the provider to use by name.
		/// </summary>
		/// <param name="providerName"> name of the provider to use. </param>
		/// <returns> the converter instance. </returns>
		public virtual JcaX509CRLConverter setProvider(string providerName)
		{
			this.helper = new NamedCertHelper(providerName);

			return this;
		}

		/// <summary>
		/// Use the configured converter to produce a X509CRL object from a X509CRLHolder object.
		/// </summary>
		/// <param name="crlHolder">  the holder to be converted </param>
		/// <returns> a X509CRL object </returns>
		/// <exception cref="CRLException"> if the conversion is unable to be made. </exception>
		public virtual X509CRL getCRL(X509CRLHolder crlHolder)
		{
			try
			{
				CertificateFactory cFact = helper.getCertificateFactory("X.509");

				return (X509CRL)cFact.generateCRL(new ByteArrayInputStream(crlHolder.getEncoded()));
			}
			catch (IOException e)
			{
				throw new ExCRLException(this, "exception parsing certificate: " + e.Message, e);
			}
			catch (NoSuchProviderException e)
			{
				throw new ExCRLException(this, "cannot find required provider:" + e.Message, e);
			}
			catch (CertificateException e)
			{
				throw new ExCRLException(this, "cannot create factory: " + e.Message, e);
			}
		}

		public class ExCRLException : CRLException
		{
			private readonly JcaX509CRLConverter outerInstance;

			internal Exception cause;

			public ExCRLException(JcaX509CRLConverter outerInstance, string msg, Exception cause) : base(msg)
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