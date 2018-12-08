namespace org.bouncycastle.openssl.jcajce
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using JcaX509CRLHolder = org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

	/// <summary>
	/// PEM generator for the original set of PEM objects used in Open SSL.
	/// </summary>
	public class JcaMiscPEMGenerator : MiscPEMGenerator
	{
		private object obj;
		private string algorithm;
		private char[] password;
		private SecureRandom random;
		private Provider provider;

		public JcaMiscPEMGenerator(object o) : base(convertObject(o))
		{
		}

		public JcaMiscPEMGenerator(object o, PEMEncryptor encryptor) : base(convertObject(o), encryptor)
		{
		}

		private static object convertObject(object o)
		{
			if (o is X509Certificate)
			{
				try
				{
					return new JcaX509CertificateHolder((X509Certificate)o);
				}
				catch (CertificateEncodingException e)
				{
					throw new IllegalArgumentException("Cannot encode object: " + e.ToString());
				}
			}
			else if (o is X509CRL)
			{
				try
				{
					return new JcaX509CRLHolder((X509CRL)o);
				}
				catch (CRLException e)
				{
					throw new IllegalArgumentException("Cannot encode object: " + e.ToString());
				}
			}
			else if (o is KeyPair)
			{
				return convertObject(((KeyPair)o).getPrivate());
			}
			else if (o is PrivateKey)
			{
				return PrivateKeyInfo.getInstance(((Key)o).getEncoded());
			}
			else if (o is PublicKey)
			{
				return SubjectPublicKeyInfo.getInstance(((PublicKey)o).getEncoded());
			}

			return o;
		}
	}

}