using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSASSAPSSparams = org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using X509Principal = org.bouncycastle.jce.X509Principal;
	using Strings = org.bouncycastle.util.Strings;

	public class X509Util
	{
		private static Hashtable algorithms = new Hashtable();
		private static Hashtable @params = new Hashtable();
		private static Set noParams = new HashSet();

		static X509Util()
		{
			algorithms.put("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.md2WithRSAEncryption);
			algorithms.put("MD2WITHRSA", PKCSObjectIdentifiers_Fields.md2WithRSAEncryption);
			algorithms.put("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.md5WithRSAEncryption);
			algorithms.put("MD5WITHRSA", PKCSObjectIdentifiers_Fields.md5WithRSAEncryption);
			algorithms.put("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption);
			algorithms.put("SHA1WITHRSA", PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption);
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
			algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160);
			algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160);
			algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128);
			algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128);
			algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256);
			algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256);
			algorithms.put("SHA1WITHDSA", X9ObjectIdentifiers_Fields.id_dsa_with_sha1);
			algorithms.put("DSAWITHSHA1", X9ObjectIdentifiers_Fields.id_dsa_with_sha1);
			algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha224);
			algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha256);
			algorithms.put("SHA384WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha384);
			algorithms.put("SHA512WITHDSA", NISTObjectIdentifiers_Fields.dsa_with_sha512);
			algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA1);
			algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers_Fields.ecdsa_with_SHA1);
			algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA224);
			algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA256);
			algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA384);
			algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers_Fields.ecdsa_with_SHA512);
			algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94);
			algorithms.put("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_94);
			algorithms.put("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);
			algorithms.put("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);
			algorithms.put("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers_Fields.gostR3411_94_with_gostR3410_2001);

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
			noParams.add(NISTObjectIdentifiers_Fields.dsa_with_sha384);
			noParams.add(NISTObjectIdentifiers_Fields.dsa_with_sha512);

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

		internal static ASN1ObjectIdentifier getAlgorithmOID(string algorithmName)
		{
			algorithmName = Strings.toUpperCase(algorithmName);

			if (algorithms.containsKey(algorithmName))
			{
				return (ASN1ObjectIdentifier)algorithms.get(algorithmName);
			}

			return new ASN1ObjectIdentifier(algorithmName);
		}

		internal static AlgorithmIdentifier getSigAlgID(ASN1ObjectIdentifier sigOid, string algorithmName)
		{
			if (noParams.contains(sigOid))
			{
				return new AlgorithmIdentifier(sigOid);
			}

			algorithmName = Strings.toUpperCase(algorithmName);

			if (@params.containsKey(algorithmName))
			{
				return new AlgorithmIdentifier(sigOid, (ASN1Encodable)@params.get(algorithmName));
			}
			else
			{
				return new AlgorithmIdentifier(sigOid, DERNull.INSTANCE);
			}
		}

		internal static Iterator getAlgNames()
		{
			Enumeration e = algorithms.keys();
			List l = new ArrayList();

			while (e.hasMoreElements())
			{
				l.add(e.nextElement());
			}

			return l.iterator();
		}

		internal static Signature getSignatureInstance(string algorithm)
		{
			return Signature.getInstance(algorithm);
		}

		internal static Signature getSignatureInstance(string algorithm, string provider)
		{
			if (!string.ReferenceEquals(provider, null))
			{
				return Signature.getInstance(algorithm, provider);
			}
			else
			{
				return Signature.getInstance(algorithm);
			}
		}

		internal static byte[] calculateSignature(ASN1ObjectIdentifier sigOid, string sigName, PrivateKey key, SecureRandom random, ASN1Encodable @object)
		{
			Signature sig;

			if (sigOid == null)
			{
				throw new IllegalStateException("no signature algorithm specified");
			}

			sig = X509Util.getSignatureInstance(sigName);

			if (random != null)
			{
				sig.initSign(key, random);
			}
			else
			{
				sig.initSign(key);
			}

			sig.update(@object.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER));

			return sig.sign();
		}

		internal static byte[] calculateSignature(ASN1ObjectIdentifier sigOid, string sigName, string provider, PrivateKey key, SecureRandom random, ASN1Encodable @object)
		{
			Signature sig;

			if (sigOid == null)
			{
				throw new IllegalStateException("no signature algorithm specified");
			}

			sig = X509Util.getSignatureInstance(sigName, provider);

			if (random != null)
			{
				sig.initSign(key, random);
			}
			else
			{
				sig.initSign(key);
			}

			sig.update(@object.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER));

			return sig.sign();
		}

		internal static X509Principal convertPrincipal(X500Principal principal)
		{
			try
			{
				return new X509Principal(principal.getEncoded());
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("cannot convert principal");
			}
		}

		public class Implementation
		{
			internal object engine;
			internal Provider provider;

			public Implementation(object engine, Provider provider)
			{
				this.engine = engine;
				this.provider = provider;
			}

			public virtual object getEngine()
			{
				return engine;
			}

			public virtual Provider getProvider()
			{
				return provider;
			}
		}

		/// <summary>
		/// see if we can find an algorithm (or its alias and what it represents) in
		/// the property table for the given provider.
		/// </summary>
		internal static Implementation getImplementation(string baseName, string algorithm, Provider prov)
		{
			algorithm = Strings.toUpperCase(algorithm);

			string alias;

			while (!string.ReferenceEquals((alias = prov.getProperty("Alg.Alias." + baseName + "." + algorithm)), null))
			{
				algorithm = alias;
			}

			string className = prov.getProperty(baseName + "." + algorithm);

			if (!string.ReferenceEquals(className, null))
			{
				try
				{
					Class cls;
					ClassLoader clsLoader = prov.GetType().getClassLoader();

					if (clsLoader != null)
					{
						cls = clsLoader.loadClass(className);
					}
					else
					{
						cls = Class.forName(className);
					}

					return new Implementation(cls.newInstance(), prov);
				}
				catch (ClassNotFoundException)
				{
					throw new IllegalStateException("algorithm " + algorithm + " in provider " + prov.getName() + @" but no class """ + className + @""" found!");
				}
				catch (Exception)
				{
					throw new IllegalStateException("algorithm " + algorithm + " in provider " + prov.getName() + @" but class """ + className + @""" inaccessible!");
				}
			}

			throw new NoSuchAlgorithmException("cannot find implementation " + algorithm + " for provider " + prov.getName());
		}

		/// <summary>
		/// return an implementation for a given algorithm/provider.
		/// If the provider is null, we grab the first avalaible who has the required algorithm.
		/// </summary>
		internal static Implementation getImplementation(string baseName, string algorithm)
		{
			Provider[] prov = Security.getProviders();

			//
			// search every provider looking for the algorithm we want.
			//
			for (int i = 0; i != prov.Length; i++)
			{
				//
				// try case insensitive
				//
				Implementation imp = getImplementation(baseName, Strings.toUpperCase(algorithm), prov[i]);
				if (imp != null)
				{
					return imp;
				}

				try
				{
					imp = getImplementation(baseName, algorithm, prov[i]);
				}
				catch (NoSuchAlgorithmException)
				{
					// continue
				}
			}

			throw new NoSuchAlgorithmException("cannot find implementation " + algorithm);
		}

		internal static Provider getProvider(string provider)
		{
			Provider prov = Security.getProvider(provider);

			if (prov == null)
			{
				throw new NoSuchProviderException("Provider " + provider + " not found");
			}

			return prov;
		}
	}

}