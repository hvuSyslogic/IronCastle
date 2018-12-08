using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.sec;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.openssl
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using EncryptedPrivateKeyInfo = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using RSAPublicKey = org.bouncycastle.asn1.pkcs.RSAPublicKey;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using X509AttributeCertificateHolder = org.bouncycastle.cert.X509AttributeCertificateHolder;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using PKCS10CertificationRequest = org.bouncycastle.pkcs.PKCS10CertificationRequest;
	using PKCS8EncryptedPrivateKeyInfo = org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using PemHeader = org.bouncycastle.util.io.pem.PemHeader;
	using PemObject = org.bouncycastle.util.io.pem.PemObject;
	using PemObjectParser = org.bouncycastle.util.io.pem.PemObjectParser;
	using PemReader = org.bouncycastle.util.io.pem.PemReader;

	/// <summary>
	/// Class for parsing OpenSSL PEM encoded streams containing
	/// X509 certificates, PKCS8 encoded keys and PKCS7 objects.
	/// <para>
	/// In the case of PKCS7 objects the reader will return a CMS ContentInfo object. Public keys will be returned as
	/// well formed SubjectPublicKeyInfo objects, private keys will be returned as well formed PrivateKeyInfo objects. In the
	/// case of a private key a PEMKeyPair will normally be returned if the encoding contains both the private and public
	/// key definition. CRLs, Certificates, PKCS#10 requests, and Attribute Certificates will generate the appropriate BC holder class.
	/// </para>
	/// </summary>
	public class PEMParser : PemReader
	{
		private readonly Map parsers = new HashMap();

		/// <summary>
		/// Create a new PEMReader
		/// </summary>
		/// <param name="reader"> the Reader </param>
		public PEMParser(Reader reader) : base(reader)
		{

			parsers.put("CERTIFICATE REQUEST", new PKCS10CertificationRequestParser(this));
			parsers.put("NEW CERTIFICATE REQUEST", new PKCS10CertificationRequestParser(this));
			parsers.put("CERTIFICATE", new X509CertificateParser(this));
			parsers.put("TRUSTED CERTIFICATE", new X509TrustedCertificateParser(this));
			parsers.put("X509 CERTIFICATE", new X509CertificateParser(this));
			parsers.put("X509 CRL", new X509CRLParser(this));
			parsers.put("PKCS7", new PKCS7Parser(this));
			parsers.put("CMS", new PKCS7Parser(this));
			parsers.put("ATTRIBUTE CERTIFICATE", new X509AttributeCertificateParser(this));
			parsers.put("EC PARAMETERS", new ECCurveParamsParser(this));
			parsers.put("PUBLIC KEY", new PublicKeyParser(this));
			parsers.put("RSA PUBLIC KEY", new RSAPublicKeyParser(this));
			parsers.put("RSA PRIVATE KEY", new KeyPairParser(this, new RSAKeyPairParser(this)));
			parsers.put("DSA PRIVATE KEY", new KeyPairParser(this, new DSAKeyPairParser(this)));
			parsers.put("EC PRIVATE KEY", new KeyPairParser(this, new ECDSAKeyPairParser(this)));
			parsers.put("ENCRYPTED PRIVATE KEY", new EncryptedPrivateKeyParser(this));
			parsers.put("PRIVATE KEY", new PrivateKeyParser(this));
		}

		/// <summary>
		/// Read the next PEM object attempting to interpret the header and
		/// create a higher level object from the content.
		/// </summary>
		/// <returns> the next object in the stream, null if no objects left. </returns>
		/// <exception cref="IOException"> in case of a parse error. </exception>
		public virtual object readObject()
		{
			PemObject obj = readPemObject();

			if (obj != null)
			{
				string type = obj.getType();
				if (parsers.containsKey(type))
				{
					return ((PemObjectParser)parsers.get(type)).parseObject(obj);
				}
				else
				{
					throw new IOException("unrecognised object: " + type);
				}
			}

			return null;
		}

		public class KeyPairParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			internal readonly PEMKeyPairParser pemKeyPairParser;

			public KeyPairParser(PEMParser outerInstance, PEMKeyPairParser pemKeyPairParser)
			{
				this.outerInstance = outerInstance;
				this.pemKeyPairParser = pemKeyPairParser;
			}

			/// <summary>
			/// Read a Key Pair
			/// </summary>
			public virtual object parseObject(PemObject obj)
			{
				bool isEncrypted = false;
				string dekInfo = null;
				List headers = obj.getHeaders();

				for (Iterator it = headers.iterator(); it.hasNext();)
				{
					PemHeader hdr = (PemHeader)it.next();

					if (hdr.getName().Equals("Proc-Type") && hdr.getValue().Equals("4,ENCRYPTED"))
					{
						isEncrypted = true;
					}
					else if (hdr.getName().Equals("DEK-Info"))
					{
						dekInfo = hdr.getValue();
					}
				}

				//
				// extract the key
				//
				byte[] keyBytes = obj.getContent();

				try
				{
					if (isEncrypted)
					{
						StringTokenizer tknz = new StringTokenizer(dekInfo, ",");
						string dekAlgName = tknz.nextToken();
						byte[] iv = Hex.decode(tknz.nextToken());

						return new PEMEncryptedKeyPair(dekAlgName, iv, keyBytes, pemKeyPairParser);
					}

					return pemKeyPairParser.parse(keyBytes);
				}
				catch (IOException e)
				{
					if (isEncrypted)
					{
						throw new PEMException("exception decoding - please check password and data.", e);
					}
					else
					{
						throw new PEMException(e.Message, e);
					}
				}
				catch (IllegalArgumentException e)
				{
					if (isEncrypted)
					{
						throw new PEMException("exception decoding - please check password and data.", e);
					}
					else
					{
						throw new PEMException(e.Message, e);
					}
				}
			}
		}

		public class DSAKeyPairParser : PEMKeyPairParser
		{
			private readonly PEMParser outerInstance;

			public DSAKeyPairParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual PEMKeyPair parse(byte[] encoding)
			{
				try
				{
					ASN1Sequence seq = ASN1Sequence.getInstance(encoding);

					if (seq.size() != 6)
					{
						throw new PEMException("malformed sequence in DSA private key");
					}

					//            ASN1Integer              v = (ASN1Integer)seq.getObjectAt(0);
					ASN1Integer p = ASN1Integer.getInstance(seq.getObjectAt(1));
					ASN1Integer q = ASN1Integer.getInstance(seq.getObjectAt(2));
					ASN1Integer g = ASN1Integer.getInstance(seq.getObjectAt(3));
					ASN1Integer y = ASN1Integer.getInstance(seq.getObjectAt(4));
					ASN1Integer x = ASN1Integer.getInstance(seq.getObjectAt(5));

					return new PEMKeyPair(new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa, new DSAParameter(p.getValue(), q.getValue(), g.getValue())), y), new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa, new DSAParameter(p.getValue(), q.getValue(), g.getValue())), x));
				}
				catch (IOException e)
				{
					throw e;
				}
				catch (Exception e)
				{
					throw new PEMException("problem creating DSA private key: " + e.ToString(), e);
				}
			}
		}

		public class ECDSAKeyPairParser : PEMKeyPairParser
		{
			private readonly PEMParser outerInstance;

			public ECDSAKeyPairParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual PEMKeyPair parse(byte[] encoding)
			{
				try
				{
					ASN1Sequence seq = ASN1Sequence.getInstance(encoding);

					ECPrivateKey pKey = ECPrivateKey.getInstance(seq);
					AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, pKey.getParameters());
					PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);

					if (pKey.getPublicKey() != null)
					{
						SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(algId, pKey.getPublicKey().getBytes());

						return new PEMKeyPair(pubInfo, privInfo);
					}
					else
					{
						return new PEMKeyPair(null, privInfo);
					}
				}
				catch (IOException e)
				{
					throw e;
				}
				catch (Exception e)
				{
					throw new PEMException("problem creating EC private key: " + e.ToString(), e);
				}
			}
		}

		public class RSAKeyPairParser : PEMKeyPairParser
		{
			private readonly PEMParser outerInstance;

			public RSAKeyPairParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual PEMKeyPair parse(byte[] encoding)
			{
				try
				{
					ASN1Sequence seq = ASN1Sequence.getInstance(encoding);

					if (seq.size() != 9)
					{
						throw new PEMException("malformed sequence in RSA private key");
					}

					RSAPrivateKey keyStruct = RSAPrivateKey.getInstance(seq);

					RSAPublicKey pubSpec = new RSAPublicKey(keyStruct.getModulus(), keyStruct.getPublicExponent());

					AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE);

					return new PEMKeyPair(new SubjectPublicKeyInfo(algId, pubSpec), new PrivateKeyInfo(algId, keyStruct));
				}
				catch (IOException e)
				{
					throw e;
				}
				catch (Exception e)
				{
					throw new PEMException("problem creating RSA private key: " + e.ToString(), e);
				}
			}
		}

		public class PublicKeyParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public PublicKeyParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual object parseObject(PemObject obj)
			{
				return SubjectPublicKeyInfo.getInstance(obj.getContent());
			}
		}

		public class RSAPublicKeyParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public RSAPublicKeyParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual object parseObject(PemObject obj)
			{
				try
				{
					RSAPublicKey rsaPubStructure = RSAPublicKey.getInstance(obj.getContent());

					return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE), rsaPubStructure);
				}
				catch (IOException e)
				{
					throw e;
				}
				catch (Exception e)
				{
					throw new PEMException("problem extracting key: " + e.ToString(), e);
				}
			}
		}

		public class X509CertificateParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public X509CertificateParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			/// <summary>
			/// Reads in a X509Certificate.
			/// </summary>
			/// <returns> the X509Certificate </returns>
			/// <exception cref="java.io.IOException"> if an I/O error occured </exception>
			public virtual object parseObject(PemObject obj)
			{
				try
				{
					return new X509CertificateHolder(obj.getContent());
				}
				catch (Exception e)
				{
					throw new PEMException("problem parsing cert: " + e.ToString(), e);
				}
			}
		}

		public class X509TrustedCertificateParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public X509TrustedCertificateParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			/// <summary>
			/// Reads in a X509Certificate.
			/// </summary>
			/// <returns> the X509Certificate </returns>
			/// <exception cref="java.io.IOException"> if an I/O error occured </exception>
			public virtual object parseObject(PemObject obj)
			{
				try
				{
					return new X509TrustedCertificateBlock(obj.getContent());
				}
				catch (Exception e)
				{
					throw new PEMException("problem parsing cert: " + e.ToString(), e);
				}
			}
		}

		public class X509CRLParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public X509CRLParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			/// <summary>
			/// Reads in a X509CRL.
			/// </summary>
			/// <returns> the X509Certificate </returns>
			/// <exception cref="java.io.IOException"> if an I/O error occured </exception>
			public virtual object parseObject(PemObject obj)
			{
				try
				{
					return new X509CRLHolder(obj.getContent());
				}
				catch (Exception e)
				{
					throw new PEMException("problem parsing cert: " + e.ToString(), e);
				}
			}
		}

		public class PKCS10CertificationRequestParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public PKCS10CertificationRequestParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			/// <summary>
			/// Reads in a PKCS10 certification request.
			/// </summary>
			/// <returns> the certificate request. </returns>
			/// <exception cref="java.io.IOException"> if an I/O error occured </exception>
			public virtual object parseObject(PemObject obj)
			{
				try
				{
					return new PKCS10CertificationRequest(obj.getContent());
				}
				catch (Exception e)
				{
					throw new PEMException("problem parsing certrequest: " + e.ToString(), e);
				}
			}
		}

		public class PKCS7Parser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public PKCS7Parser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			/// <summary>
			/// Reads in a PKCS7 object. This returns a ContentInfo object suitable for use with the CMS
			/// API.
			/// </summary>
			/// <returns> the X509Certificate </returns>
			/// <exception cref="java.io.IOException"> if an I/O error occured </exception>
			public virtual object parseObject(PemObject obj)
			{
				try
				{
					ASN1InputStream aIn = new ASN1InputStream(obj.getContent());

					return ContentInfo.getInstance(aIn.readObject());
				}
				catch (Exception e)
				{
					throw new PEMException("problem parsing PKCS7 object: " + e.ToString(), e);
				}
			}
		}

		public class X509AttributeCertificateParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public X509AttributeCertificateParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual object parseObject(PemObject obj)
			{
				return new X509AttributeCertificateHolder(obj.getContent());
			}
		}

		public class ECCurveParamsParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public ECCurveParamsParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual object parseObject(PemObject obj)
			{
				try
				{
					object param = ASN1Primitive.fromByteArray(obj.getContent());

					if (param is ASN1ObjectIdentifier)
					{
						return ASN1Primitive.fromByteArray(obj.getContent());
					}
					else if (param is ASN1Sequence)
					{
						return X9ECParameters.getInstance(param);
					}
					else
					{
						return null; // implicitly CA
					}
				}
				catch (IOException e)
				{
					throw e;
				}
				catch (Exception e)
				{
					throw new PEMException("exception extracting EC named curve: " + e.ToString());
				}
			}
		}

		public class EncryptedPrivateKeyParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public EncryptedPrivateKeyParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			/// <summary>
			/// Reads in an EncryptedPrivateKeyInfo
			/// </summary>
			/// <returns> the X509Certificate </returns>
			/// <exception cref="java.io.IOException"> if an I/O error occured </exception>
			public virtual object parseObject(PemObject obj)
			{
				try
				{
					return new PKCS8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo.getInstance(obj.getContent()));
				}
				catch (Exception e)
				{
					throw new PEMException("problem parsing ENCRYPTED PRIVATE KEY: " + e.ToString(), e);
				}
			}
		}

		public class PrivateKeyParser : PemObjectParser
		{
			private readonly PEMParser outerInstance;

			public PrivateKeyParser(PEMParser outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public virtual object parseObject(PemObject obj)
			{
				try
				{
					return PrivateKeyInfo.getInstance(obj.getContent());
				}
				catch (Exception e)
				{
					throw new PEMException("problem parsing PRIVATE KEY: " + e.ToString(), e);
				}
			}
		}
	}

}