using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jce
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using CertificationRequest = org.bouncycastle.asn1.pkcs.CertificationRequest;
	using CertificationRequestInfo = org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSASSAPSSparams = org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// A class for verifying and creating PKCS10 Certification requests. 
	/// <pre>
	/// CertificationRequest ::= SEQUENCE {
	///   certificationRequestInfo  CertificationRequestInfo,
	///   signatureAlgorithm        AlgorithmIdentifier{{ SignatureAlgorithms }},
	///   signature                 BIT STRING
	/// }
	/// 
	/// CertificationRequestInfo ::= SEQUENCE {
	///   version             INTEGER { v1(0) } (v1,...),
	///   subject             Name,
	///   subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
	///   attributes          [0] Attributes{{ CRIAttributes }}
	///  }
	/// 
	///  Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
	/// 
	///  Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
	///    type    ATTRIBUTE.&amp;id({IOSet}),
	///    values  SET SIZE(1..MAX) OF ATTRIBUTE.&amp;Type({IOSet}{\@type})
	///  }
	/// </pre> </summary>
	/// @deprecated use classes in org.bouncycastle.pkcs. 
	public class PKCS10CertificationRequest : CertificationRequest
	{
		private static Hashtable algorithms = new Hashtable();
		private static Hashtable @params = new Hashtable();
		private static Hashtable keyAlgorithms = new Hashtable();
		private static Hashtable oids = new Hashtable();
		private static Set noParams = new HashSet();

		static PKCS10CertificationRequest()
		{
			algorithms.put("MD2WITHRSAENCRYPTION", new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"));
			algorithms.put("MD2WITHRSA", new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"));
			algorithms.put("MD5WITHRSAENCRYPTION", new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"));
			algorithms.put("MD5WITHRSA", new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"));
			algorithms.put("RSAWITHMD5", new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"));
			algorithms.put("SHA1WITHRSAENCRYPTION", new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));
			algorithms.put("SHA1WITHRSA", new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));
			algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption);
			algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption);
			algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption);
			algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption);
			algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption);
			algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption);
			algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption);
			algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption);
			algorithms.put("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA224WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers_Fields.id_RSASSA_PSS);
			algorithms.put("RSAWITHSHA1", new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));
			algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128);
			algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128);
			algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160);
			algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160);
			algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256);
			algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256);
			algorithms.put("SHA1WITHDSA", new ASN1ObjectIdentifier("1.2.840.10040.4.3"));
			algorithms.put("DSAWITHSHA1", new ASN1ObjectIdentifier("1.2.840.10040.4.3"));
			algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha224);
			algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha256);
			algorithms.put("SHA384WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha384);
			algorithms.put("SHA512WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha512);
			algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA1);
			algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA224);
			algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA256);
			algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA384);
			algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA512);
			algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers_Fields.ecdsa_with_SHA1);
			algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94);
			algorithms.put("GOST3410WITHGOST3411", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94);
			algorithms.put("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);
			algorithms.put("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);
			algorithms.put("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);

			//
			// reverse mappings
			//
			oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
			oids.put(PKCSObjectIdentifiers_Fields.sha224WithRSAEncryption, "SHA224WITHRSA");
			oids.put(PKCSObjectIdentifiers_Fields.sha256WithRSAEncryption, "SHA256WITHRSA");
			oids.put(PKCSObjectIdentifiers_Fields.sha384WithRSAEncryption, "SHA384WITHRSA");
			oids.put(PKCSObjectIdentifiers_Fields.sha512WithRSAEncryption, "SHA512WITHRSA");
			oids.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
			oids.put(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");

			oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
			oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
			oids.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1, "SHA1WITHECDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA224, "SHA224WITHECDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA256, "SHA256WITHECDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA384, "SHA384WITHECDSA");
			oids.put(X9ObjectIdentifiers_Fields.ecdsa_with_SHA512, "SHA512WITHECDSA");
			oids.put(OIWObjectIdentifiers_Fields.sha1WithRSA, "SHA1WITHRSA");
			oids.put(OIWObjectIdentifiers_Fields.dsaWithSHA1, "SHA1WITHDSA");
			oids.put(NISTObjectIdentifiers_Fields.dsa_with_sha224, "SHA224WITHDSA");
			oids.put(NISTObjectIdentifiers_Fields.dsa_with_sha256, "SHA256WITHDSA");

			//
			// key types
			//
			keyAlgorithms.put(PKCSObjectIdentifiers_Fields.rsaEncryption, "RSA");
			keyAlgorithms.put(X9ObjectIdentifiers_Fields.id_dsa, "DSA");

			//
			// According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field. 
			// The parameters field SHALL be NULL for RSA based signature algorithms.
			//
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA1);
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA224);
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA256);
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA384);
			noParams.add(X9ObjectIdentifiers_Fields.ecdsa_with_SHA512);
			noParams.add(X9ObjectIdentifiers_Fields.id_dsa_with_sha1);
			noParams.add(NISTObjectIdentifiers_Fields.dsa_with_sha224);
			noParams.add(NISTObjectIdentifiers_Fields.dsa_with_sha256);

			//
			// RFC 4491
			//
			noParams.add(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94);
			noParams.add(CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);
			//
			// explicit params
			//
			AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE);
			@params.put("SHA1WITHRSAANDMGF1", creatPSSParams(sha1AlgId, 20));

			AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha224, DERNull.INSTANCE);
			@params.put("SHA224WITHRSAANDMGF1", creatPSSParams(sha224AlgId, 28));

			AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha256, DERNull.INSTANCE);
			@params.put("SHA256WITHRSAANDMGF1", creatPSSParams(sha256AlgId, 32));

			AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha384, DERNull.INSTANCE);
			@params.put("SHA384WITHRSAANDMGF1", creatPSSParams(sha384AlgId, 48));

			AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512, DERNull.INSTANCE);
			@params.put("SHA512WITHRSAANDMGF1", creatPSSParams(sha512AlgId, 64));
		}

		private static RSASSAPSSparams creatPSSParams(AlgorithmIdentifier hashAlgId, int saltSize)
		{
			return new RSASSAPSSparams(hashAlgId, new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, hashAlgId), new ASN1Integer(saltSize), new ASN1Integer(1));
		}

		private static ASN1Sequence toDERSequence(byte[] bytes)
		{
			try
			{
				ASN1InputStream dIn = new ASN1InputStream(bytes);

				return (ASN1Sequence)dIn.readObject();
			}
			catch (Exception)
			{
				throw new IllegalArgumentException("badly encoded request");
			}
		}

		/// <summary>
		/// construct a PKCS10 certification request from a DER encoded
		/// byte stream.
		/// </summary>
		public PKCS10CertificationRequest(byte[] bytes) : base(toDERSequence(bytes))
		{
		}

		public PKCS10CertificationRequest(ASN1Sequence sequence) : base(sequence)
		{
		}

		/// <summary>
		/// create a PKCS10 certfication request using the BC provider.
		/// </summary>
		public PKCS10CertificationRequest(string signatureAlgorithm, X509Name subject, PublicKey key, ASN1Set attributes, PrivateKey signingKey) : this(signatureAlgorithm, subject, key, attributes, signingKey, BouncyCastleProvider.PROVIDER_NAME)
		{
		}

		private static X509Name convertName(X500Principal name)
		{
			try
			{
				return new X509Principal(name.getEncoded());
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("can't convert name");
			}
		}

		/// <summary>
		/// create a PKCS10 certfication request using the BC provider.
		/// </summary>
		public PKCS10CertificationRequest(string signatureAlgorithm, X500Principal subject, PublicKey key, ASN1Set attributes, PrivateKey signingKey) : this(signatureAlgorithm, convertName(subject), key, attributes, signingKey, BouncyCastleProvider.PROVIDER_NAME)
		{
		}

		/// <summary>
		/// create a PKCS10 certfication request using the named provider.
		/// </summary>
		public PKCS10CertificationRequest(string signatureAlgorithm, X500Principal subject, PublicKey key, ASN1Set attributes, PrivateKey signingKey, string provider) : this(signatureAlgorithm, convertName(subject), key, attributes, signingKey, provider)
		{
		}

		/// <summary>
		/// create a PKCS10 certfication request using the named provider.
		/// </summary>
		public PKCS10CertificationRequest(string signatureAlgorithm, X509Name subject, PublicKey key, ASN1Set attributes, PrivateKey signingKey, string provider)
		{
			string algorithmName = Strings.toUpperCase(signatureAlgorithm);
			ASN1ObjectIdentifier sigOID = (ASN1ObjectIdentifier)algorithms.get(algorithmName);

			if (sigOID == null)
			{
				try
				{
					sigOID = new ASN1ObjectIdentifier(algorithmName);
				}
				catch (Exception)
				{
					throw new IllegalArgumentException("Unknown signature type requested");
				}
			}

			if (subject == null)
			{
				throw new IllegalArgumentException("subject must not be null");
			}

			if (key == null)
			{
				throw new IllegalArgumentException("public key must not be null");
			}

			if (noParams.contains(sigOID))
			{
				this.sigAlgId = new AlgorithmIdentifier(sigOID);
			}
			else if (@params.containsKey(algorithmName))
			{
				this.sigAlgId = new AlgorithmIdentifier(sigOID, (ASN1Encodable)@params.get(algorithmName));
			}
			else
			{
				this.sigAlgId = new AlgorithmIdentifier(sigOID, DERNull.INSTANCE);
			}

			try
			{
				ASN1Sequence seq = (ASN1Sequence)ASN1Primitive.fromByteArray(key.getEncoded());
				this.reqInfo = new CertificationRequestInfo(subject, SubjectPublicKeyInfo.getInstance(seq), attributes);
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("can't encode public key");
			}

			Signature sig;
			if (string.ReferenceEquals(provider, null))
			{
				sig = Signature.getInstance(signatureAlgorithm);
			}
			else
			{
				sig = Signature.getInstance(signatureAlgorithm, provider);
			}

			sig.initSign(signingKey);

			try
			{
				sig.update(reqInfo.getEncoded(ASN1Encoding_Fields.DER));
			}
			catch (Exception e)
			{
				throw new IllegalArgumentException("exception encoding TBS cert request - " + e);
			}

			this.sigBits = new DERBitString(sig.sign());
		}

		/// <summary>
		/// return the public key associated with the certification request -
		/// the public key is created using the BC provider.
		/// </summary>
		public virtual PublicKey getPublicKey()
		{
			return getPublicKey(BouncyCastleProvider.PROVIDER_NAME);
		}

		public virtual PublicKey getPublicKey(string provider)
		{
			SubjectPublicKeyInfo subjectPKInfo = reqInfo.getSubjectPublicKeyInfo();


			try
			{
				X509EncodedKeySpec xspec = new X509EncodedKeySpec((new DERBitString(subjectPKInfo)).getOctets());
				AlgorithmIdentifier keyAlg = subjectPKInfo.getAlgorithm();
				try
				{
					if (string.ReferenceEquals(provider, null))
					{
						return KeyFactory.getInstance(keyAlg.getAlgorithm().getId()).generatePublic(xspec);
					}
					else
					{
						return KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), provider).generatePublic(xspec);
					}
				}
				catch (NoSuchAlgorithmException e)
				{
					//
					// try an alternate
					//
					if (keyAlgorithms.get(keyAlg.getAlgorithm()) != null)
					{
						string keyAlgorithm = (string)keyAlgorithms.get(keyAlg.getAlgorithm());

						if (string.ReferenceEquals(provider, null))
						{
							return KeyFactory.getInstance(keyAlgorithm).generatePublic(xspec);
						}
						else
						{
							return KeyFactory.getInstance(keyAlgorithm, provider).generatePublic(xspec);
						}
					}

					throw e;
				}
			}
			catch (InvalidKeySpecException)
			{
				throw new InvalidKeyException("error decoding public key");
			}
			catch (IOException)
			{
				throw new InvalidKeyException("error decoding public key");
			}
		}

		/// <summary>
		/// verify the request using the BC provider.
		/// </summary>
		public virtual bool verify()
		{
			return verify(BouncyCastleProvider.PROVIDER_NAME);
		}

		/// <summary>
		/// verify the request using the passed in provider.
		/// </summary>
		public virtual bool verify(string provider)
		{
			return verify(this.getPublicKey(provider), provider);
		}

		/// <summary>
		/// verify the request using the passed in public key and the provider..
		/// </summary>
		public virtual bool verify(PublicKey pubKey, string provider)
		{
			Signature sig;

			try
			{
				if (string.ReferenceEquals(provider, null))
				{
					sig = Signature.getInstance(getSignatureName(sigAlgId));
				}
				else
				{
					sig = Signature.getInstance(getSignatureName(sigAlgId), provider);
				}
			}
			catch (NoSuchAlgorithmException e)
			{
				//
				// try an alternate
				//
				if (oids.get(sigAlgId.getAlgorithm()) != null)
				{
					string signatureAlgorithm = (string)oids.get(sigAlgId.getAlgorithm());

					if (string.ReferenceEquals(provider, null))
					{
						sig = Signature.getInstance(signatureAlgorithm);
					}
					else
					{
						sig = Signature.getInstance(signatureAlgorithm, provider);
					}
				}
				else
				{
					throw e;
				}
			}

			setSignatureParameters(sig, sigAlgId.getParameters());

			sig.initVerify(pubKey);

			try
			{
				sig.update(reqInfo.getEncoded(ASN1Encoding_Fields.DER));
			}
			catch (Exception e)
			{
				throw new SignatureException("exception encoding TBS cert request - " + e);
			}

			return sig.verify(sigBits.getOctets());
		}

		/// <summary>
		/// return a DER encoded byte array representing this object
		/// </summary>
		public override byte[] getEncoded()
		{
			try
			{
				return this.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException e)
			{
				throw new RuntimeException(e.ToString());
			}
		}

		private void setSignatureParameters(Signature signature, ASN1Encodable @params)
		{
			if (@params != null && !DERNull.INSTANCE.Equals(@params))
			{
				AlgorithmParameters sigParams = AlgorithmParameters.getInstance(signature.getAlgorithm(), signature.getProvider());

				try
				{
					sigParams.init(@params.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER));
				}
				catch (IOException e)
				{
					throw new SignatureException("IOException decoding parameters: " + e.Message);
				}

				if (signature.getAlgorithm().EndsWith("MGF1"))
				{
					try
					{
						signature.setParameter(sigParams.getParameterSpec(typeof(PSSParameterSpec)));
					}
					catch (GeneralSecurityException e)
					{
						throw new SignatureException("Exception extracting parameters: " + e.Message);
					}
				}
			}
		}

		internal static string getSignatureName(AlgorithmIdentifier sigAlgId)
		{
			ASN1Encodable @params = sigAlgId.getParameters();

			if (@params != null && !DERNull.INSTANCE.Equals(@params))
			{
				if (sigAlgId.getAlgorithm().Equals(PKCSObjectIdentifiers_Fields.id_RSASSA_PSS))
				{
					RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(@params);
					return getDigestAlgName(rsaParams.getHashAlgorithm().getAlgorithm()) + "withRSAandMGF1";
				}
			}

			return sigAlgId.getAlgorithm().getId();
		}

		private static string getDigestAlgName(ASN1ObjectIdentifier digestAlgOID)
		{
			if (PKCSObjectIdentifiers_Fields.md5.Equals(digestAlgOID))
			{
				return "MD5";
			}
			else if (OIWObjectIdentifiers_Fields.idSHA1.Equals(digestAlgOID))
			{
				return "SHA1";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha224.Equals(digestAlgOID))
			{
				return "SHA224";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha256.Equals(digestAlgOID))
			{
				return "SHA256";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha384.Equals(digestAlgOID))
			{
				return "SHA384";
			}
			else if (NISTObjectIdentifiers_Fields.id_sha512.Equals(digestAlgOID))
			{
				return "SHA512";
			}
			else if (TeleTrusTObjectIdentifiers_Fields.ripemd128.Equals(digestAlgOID))
			{
				return "RIPEMD128";
			}
			else if (TeleTrusTObjectIdentifiers_Fields.ripemd160.Equals(digestAlgOID))
			{
				return "RIPEMD160";
			}
			else if (TeleTrusTObjectIdentifiers_Fields.ripemd256.Equals(digestAlgOID))
			{
				return "RIPEMD256";
			}
			else if (CryptoProObjectIdentifiers_Fields.gostR3411.Equals(digestAlgOID))
			{
				return "GOST3411";
			}
			else
			{
				return digestAlgOID.getId();
			}
		}
	}

}