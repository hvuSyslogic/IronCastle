using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.openssl
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using X509AttributeCertificateHolder = org.bouncycastle.cert.X509AttributeCertificateHolder;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using PKCS10CertificationRequest = org.bouncycastle.pkcs.PKCS10CertificationRequest;
	using PKCS8EncryptedPrivateKeyInfo = org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
	using Strings = org.bouncycastle.util.Strings;
	using PemGenerationException = org.bouncycastle.util.io.pem.PemGenerationException;
	using PemHeader = org.bouncycastle.util.io.pem.PemHeader;
	using PemObject = org.bouncycastle.util.io.pem.PemObject;
	using PemObjectGenerator = org.bouncycastle.util.io.pem.PemObjectGenerator;

	/// <summary>
	/// PEM generator for the original set of PEM objects used in Open SSL.
	/// </summary>
	public class MiscPEMGenerator : PemObjectGenerator
	{
		private static readonly ASN1ObjectIdentifier[] dsaOids = new ASN1ObjectIdentifier[] {X9ObjectIdentifiers_Fields.id_dsa, OIWObjectIdentifiers_Fields.dsaWithSHA1};

		private static readonly byte[] hexEncodingTable = new byte[] {(byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9', (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F'};

		private readonly object obj;
		private readonly PEMEncryptor encryptor;

		public MiscPEMGenerator(object o)
		{
			this.obj = o; // use of this confuses some earlier JDKs.
			this.encryptor = null;
		}

		public MiscPEMGenerator(object o, PEMEncryptor encryptor)
		{
			this.obj = o;
			this.encryptor = encryptor;
		}

		private PemObject createPemObject(object o)
		{
			string type;
			byte[] encoding;

			if (o is PemObject)
			{
				return (PemObject)o;
			}
			if (o is PemObjectGenerator)
			{
				return ((PemObjectGenerator)o).generate();
			}
			if (o is X509CertificateHolder)
			{
				type = "CERTIFICATE";

				encoding = ((X509CertificateHolder)o).getEncoded();
			}
			else if (o is X509CRLHolder)
			{
				type = "X509 CRL";

				encoding = ((X509CRLHolder)o).getEncoded();
			}
			else if (o is X509TrustedCertificateBlock)
			{
				type = "TRUSTED CERTIFICATE";

				encoding = ((X509TrustedCertificateBlock)o).getEncoded();
			}
			else if (o is PrivateKeyInfo)
			{
				PrivateKeyInfo info = (PrivateKeyInfo)o;
				ASN1ObjectIdentifier algOID = info.getPrivateKeyAlgorithm().getAlgorithm();

				if (algOID.Equals(PKCSObjectIdentifiers_Fields.rsaEncryption))
				{
					type = "RSA PRIVATE KEY";

					encoding = info.parsePrivateKey().toASN1Primitive().getEncoded();
				}
				else if (algOID.Equals(dsaOids[0]) || algOID.Equals(dsaOids[1]))
				{
					type = "DSA PRIVATE KEY";

					DSAParameter p = DSAParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
					ASN1EncodableVector v = new ASN1EncodableVector();

					v.add(new ASN1Integer(0));
					v.add(new ASN1Integer(p.getP()));
					v.add(new ASN1Integer(p.getQ()));
					v.add(new ASN1Integer(p.getG()));

					BigInteger x = ASN1Integer.getInstance(info.parsePrivateKey()).getValue();
					BigInteger y = p.getG().modPow(x, p.getP());

					v.add(new ASN1Integer(y));
					v.add(new ASN1Integer(x));

					encoding = (new DERSequence(v)).getEncoded();
				}
				else if (algOID.Equals(X9ObjectIdentifiers_Fields.id_ecPublicKey))
				{
					type = "EC PRIVATE KEY";

					encoding = info.parsePrivateKey().toASN1Primitive().getEncoded();
				}
				else
				{
					throw new IOException("Cannot identify private key");
				}
			}
			else if (o is SubjectPublicKeyInfo)
			{
				type = "PUBLIC KEY";

				encoding = ((SubjectPublicKeyInfo)o).getEncoded();
			}
			else if (o is X509AttributeCertificateHolder)
			{
				type = "ATTRIBUTE CERTIFICATE";
				encoding = ((X509AttributeCertificateHolder)o).getEncoded();
			}
			else if (o is PKCS10CertificationRequest)
			{
				type = "CERTIFICATE REQUEST";
				encoding = ((PKCS10CertificationRequest)o).getEncoded();
			}
			else if (o is PKCS8EncryptedPrivateKeyInfo)
			{
				type = "ENCRYPTED PRIVATE KEY";
				encoding = ((PKCS8EncryptedPrivateKeyInfo)o).getEncoded();
			}
			else if (o is ContentInfo)
			{
				type = "PKCS7";
				encoding = ((ContentInfo)o).getEncoded();
			}
			else
			{
				throw new PemGenerationException("unknown object passed - can't encode.");
			}

			if (encryptor != null)
			{
				string dekAlgName = Strings.toUpperCase(encryptor.getAlgorithm());

				// Note: For backward compatibility
				if (dekAlgName.Equals("DESEDE"))
				{
					dekAlgName = "DES-EDE3-CBC";
				}


				byte[] iv = encryptor.getIV();

				byte[] encData = encryptor.encrypt(encoding);

				List headers = new ArrayList(2);

				headers.add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
				headers.add(new PemHeader("DEK-Info", dekAlgName + "," + getHexEncoded(iv)));

				return new PemObject(type, headers, encData);
			}
			return new PemObject(type, encoding);
		}

		private string getHexEncoded(byte[] bytes)
		{
			char[] chars = new char[bytes.Length * 2];

			for (int i = 0; i != bytes.Length; i++)
			{
				int v = bytes[i] & 0xff;

				chars[2 * i] = (char)(hexEncodingTable[((int)((uint)v >> 4))]);
				chars[2 * i + 1] = (char)(hexEncodingTable[v & 0xf]);
			}

			return new string(chars);
		}

		public virtual PemObject generate()
		{
			try
			{
				return createPemObject(obj);
			}
			catch (IOException e)
			{
				throw new PemGenerationException("encoding exception: " + e.Message, e);
			}
		}
	}

}