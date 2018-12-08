namespace org.bouncycastle.openssl.jcajce
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateConverter = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
	using JcaPKIXIdentity = org.bouncycastle.pkix.jcajce.JcaPKIXIdentity;

	/// <summary>
	/// Builder for a private/public identity object representing a "user"
	/// </summary>
	public class JcaPKIXIdentityBuilder
	{
		private JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter();
		private JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();

		public JcaPKIXIdentityBuilder()
		{

		}

		public virtual JcaPKIXIdentityBuilder setProvider(Provider provider)
		{
			this.keyConverter = keyConverter.setProvider(provider);
			this.certConverter = certConverter.setProvider(provider);

			return this;
		}

		public virtual JcaPKIXIdentityBuilder setProvider(string providerName)
		{
			this.keyConverter = keyConverter.setProvider(providerName);
			this.certConverter = certConverter.setProvider(providerName);

			return this;
		}

		/// <summary>
		/// Build an identity from the passed in key and certificate file in PEM format.
		/// </summary>
		/// <param name="keyFile">  the PEM file containing the key </param>
		/// <param name="certificateFile"> the PEM file containing the certificate </param>
		/// <returns> an identity object. </returns>
		/// <exception cref="IOException"> on a general parsing error. </exception>
		/// <exception cref="CertificateException"> on a certificate parsing error. </exception>
		public virtual JcaPKIXIdentity build(File keyFile, File certificateFile)
		{
			checkFile(keyFile);
			checkFile(certificateFile);

			FileInputStream keyStream = new FileInputStream(keyFile);
			FileInputStream certificateStream = new FileInputStream(certificateFile);

			JcaPKIXIdentity rv = build(keyStream, certificateStream);

			keyStream.close();
			certificateStream.close();

			return rv;
		}

		/// <summary>
		/// Build an identity from the passed in key and certificate stream in PEM format.
		/// </summary>
		/// <param name="keyStream">  the PEM stream containing the key </param>
		/// <param name="certificateStream"> the PEM stream containing the certificate </param>
		/// <returns> an identity object. </returns>
		/// <exception cref="IOException"> on a general parsing error. </exception>
		/// <exception cref="CertificateException"> on a certificate parsing error. </exception>
		public virtual JcaPKIXIdentity build(InputStream keyStream, InputStream certificateStream)
		{
			PEMParser keyParser = new PEMParser(new InputStreamReader(keyStream));

			PrivateKey privKey;

			object keyObj = keyParser.readObject();
			if (keyObj is PEMKeyPair)
			{
				PEMKeyPair kp = (PEMKeyPair)keyObj;

				privKey = keyConverter.getPrivateKey(kp.getPrivateKeyInfo());
			}
			else if (keyObj is PrivateKeyInfo)
			{
				privKey = keyConverter.getPrivateKey((PrivateKeyInfo)keyObj);
			}
			else
			{
				throw new IOException("unrecognised private key file"); // TODO: handle encrypted private keys
			}

			PEMParser certParser = new PEMParser(new InputStreamReader(certificateStream));

			List certs = new ArrayList();
			object certObj;
			while ((certObj = certParser.readObject()) != null)
			{
				certs.add(certConverter.getCertificate((X509CertificateHolder)certObj));
			}

			return new JcaPKIXIdentity(privKey, (X509Certificate[])certs.toArray(new X509Certificate[certs.size()]));
		}

		private void checkFile(File file)
		{
			if (file.canRead())
			{
				if (file.exists())
				{
					throw new IOException("Unable to open file " + file.getPath() + " for reading.");
				}
				throw new FileNotFoundException("Unable to open " + file.getPath() + ": it does not exist.");
			}
		}
	}

}