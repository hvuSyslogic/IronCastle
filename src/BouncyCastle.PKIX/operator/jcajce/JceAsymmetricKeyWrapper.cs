using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.@operator.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using Gost2814789EncryptedKey = org.bouncycastle.asn1.cryptopro.Gost2814789EncryptedKey;
	using GostR3410KeyTransport = org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;
	using GostR3410TransportParameters = org.bouncycastle.asn1.cryptopro.GostR3410TransportParameters;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RSAESOAEPparams = org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using GOST28147WrapParameterSpec = org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using Arrays = org.bouncycastle.util.Arrays;

	public class JceAsymmetricKeyWrapper : AsymmetricKeyWrapper
	{
		private static readonly Set gostAlgs = new HashSet();

		static JceAsymmetricKeyWrapper()
		{
			gostAlgs.add(CryptoProObjectIdentifiers_Fields.gostR3410_2001_CryptoPro_ESDH);
			gostAlgs.add(CryptoProObjectIdentifiers_Fields.gostR3410_2001);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_agreement_gost_3410_12_256);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_agreement_gost_3410_12_512);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_256);
			gostAlgs.add(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512);
			digests.put("SHA-1", new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE));
			digests.put("SHA-1", new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE));
			digests.put("SHA224", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha224, DERNull.INSTANCE));
			digests.put("SHA-224", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha224, DERNull.INSTANCE));
			digests.put("SHA256", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha256, DERNull.INSTANCE));
			digests.put("SHA-256", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha256, DERNull.INSTANCE));
			digests.put("SHA384", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha384, DERNull.INSTANCE));
			digests.put("SHA-384", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha384, DERNull.INSTANCE));
			digests.put("SHA512", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512, DERNull.INSTANCE));
			digests.put("SHA-512", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512, DERNull.INSTANCE));
			digests.put("SHA512/224", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512_224, DERNull.INSTANCE));
			digests.put("SHA-512/224", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512_224, DERNull.INSTANCE));
			digests.put("SHA-512(224)", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512_224, DERNull.INSTANCE));
			digests.put("SHA512/256", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512_256, DERNull.INSTANCE));
			digests.put("SHA-512/256", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512_256, DERNull.INSTANCE));
			digests.put("SHA-512(256)", new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512_256, DERNull.INSTANCE));
		}

		internal static bool isGOST(ASN1ObjectIdentifier algorithm)
		{
			return gostAlgs.contains(algorithm);
		}

		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private Map extraMappings = new HashMap();
		private PublicKey publicKey;
		private SecureRandom random;

		public JceAsymmetricKeyWrapper(PublicKey publicKey) : base(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getAlgorithm())
		{

			this.publicKey = publicKey;
		}

		public JceAsymmetricKeyWrapper(X509Certificate certificate) : this(certificate.getPublicKey())
		{
		}

		/// <summary>
		/// Create a wrapper, overriding the algorithm type that is stored in the public key.
		/// </summary>
		/// <param name="algorithmIdentifier"> identifier for encryption algorithm to be used. </param>
		/// <param name="publicKey"> the public key to be used. </param>
		public JceAsymmetricKeyWrapper(AlgorithmIdentifier algorithmIdentifier, PublicKey publicKey) : base(algorithmIdentifier)
		{

			this.publicKey = publicKey;
		}

		/// <summary>
		/// Create a wrapper, overriding the algorithm type that is stored in the public key.
		/// </summary>
		/// <param name="algorithmParameterSpec"> the parameterSpec for encryption algorithm to be used. </param>
		/// <param name="publicKey"> the public key to be used. </param>
		public JceAsymmetricKeyWrapper(AlgorithmParameterSpec algorithmParameterSpec, PublicKey publicKey) : base(extractFromSpec(algorithmParameterSpec))
		{

			this.publicKey = publicKey;
		}


		public virtual JceAsymmetricKeyWrapper setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JceAsymmetricKeyWrapper setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual JceAsymmetricKeyWrapper setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		/// <summary>
		/// Internally algorithm ids are converted into cipher names using a lookup table. For some providers
		/// the standard lookup table won't work. Use this method to establish a specific mapping from an
		/// algorithm identifier to a specific algorithm.
		/// <para>
		///     For example:
		/// <pre>
		///     unwrapper.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA");
		/// </pre>
		/// </para>
		/// </summary>
		/// <param name="algorithm">  OID of algorithm in recipient. </param>
		/// <param name="algorithmName"> JCE algorithm name to use. </param>
		/// <returns> the current Wrapper. </returns>
		public virtual JceAsymmetricKeyWrapper setAlgorithmMapping(ASN1ObjectIdentifier algorithm, string algorithmName)
		{
			extraMappings.put(algorithm, algorithmName);

			return this;
		}

		public override byte[] generateWrappedKey(GenericKey encryptionKey)
		{
			byte[] encryptedKeyBytes = null;

			if (isGOST(getAlgorithmIdentifier().getAlgorithm()))
			{
				try
				{
					if (random == null)
					{
						random = new SecureRandom();
					}
					KeyPairGenerator kpGen = helper.createKeyPairGenerator(getAlgorithmIdentifier().getAlgorithm());

					kpGen.initialize(((ECPublicKey)publicKey).getParams(), random);

					KeyPair ephKp = kpGen.generateKeyPair();

					byte[] ukm = new byte[8];

					random.nextBytes(ukm);

					SubjectPublicKeyInfo ephKeyInfo = SubjectPublicKeyInfo.getInstance(ephKp.getPublic().getEncoded());

					GostR3410TransportParameters transParams;

					if (ephKeyInfo.getAlgorithm().getAlgorithm().on(RosstandartObjectIdentifiers_Fields.id_tc26))
					{
						transParams = new GostR3410TransportParameters(RosstandartObjectIdentifiers_Fields.id_tc26_gost_28147_param_Z, ephKeyInfo, ukm);
					}
					else
					{
						transParams = new GostR3410TransportParameters(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_A_ParamSet, ephKeyInfo, ukm);
					}

					KeyAgreement agreement = helper.createKeyAgreement(getAlgorithmIdentifier().getAlgorithm());

					agreement.init(ephKp.getPrivate(), new UserKeyingMaterialSpec(transParams.getUkm()));

					agreement.doPhase(publicKey, true);

					SecretKey key = agreement.generateSecret(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_KeyWrap.getId());

					byte[] encKey = OperatorUtils.getJceKey(encryptionKey).getEncoded();

					Cipher keyCipher = helper.createCipher(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_KeyWrap);

					keyCipher.init(Cipher.WRAP_MODE, key, new GOST28147WrapParameterSpec(transParams.getEncryptionParamSet(), transParams.getUkm()));

					byte[] keyData = keyCipher.wrap(new SecretKeySpec(encKey, "GOST"));

					GostR3410KeyTransport transport = new GostR3410KeyTransport(new Gost2814789EncryptedKey(Arrays.copyOfRange(keyData, 0, 32), Arrays.copyOfRange(keyData, 32, 36)), transParams);

					return transport.getEncoded();
				}
				catch (Exception e)
				{
					throw new OperatorException("exception wrapping key: " + e.Message, e);
				}
			}
			else
			{
				Cipher keyEncryptionCipher = helper.createAsymmetricWrapper(getAlgorithmIdentifier().getAlgorithm(), extraMappings);
				AlgorithmParameters algParams = helper.createAlgorithmParameters(this.getAlgorithmIdentifier());

				try
				{
					if (algParams != null)
					{
						keyEncryptionCipher.init(Cipher.WRAP_MODE, publicKey, algParams, random);
					}
					else
					{
						keyEncryptionCipher.init(Cipher.WRAP_MODE, publicKey, random);
					}
					encryptedKeyBytes = keyEncryptionCipher.wrap(OperatorUtils.getJceKey(encryptionKey));
				}
				catch (InvalidKeyException)
				{
				}
				catch (GeneralSecurityException)
				{
				}
				catch (IllegalStateException)
				{
				}
				catch (UnsupportedOperationException)
				{
				}
				catch (ProviderException)
				{
				}

				// some providers do not support WRAP (this appears to be only for asymmetric algorithms)
				if (encryptedKeyBytes == null)
				{
					try
					{
						keyEncryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
						encryptedKeyBytes = keyEncryptionCipher.doFinal(OperatorUtils.getJceKey(encryptionKey).getEncoded());
					}
					catch (InvalidKeyException e)
					{
						throw new OperatorException("unable to encrypt contents key", e);
					}
					catch (GeneralSecurityException e)
					{
						throw new OperatorException("unable to encrypt contents key", e);
					}
				}
			}

			return encryptedKeyBytes;
		}

		private static AlgorithmIdentifier extractFromSpec(AlgorithmParameterSpec algorithmParameterSpec)
		{
			if (algorithmParameterSpec is OAEPParameterSpec)
			{
				OAEPParameterSpec oaepSpec = (OAEPParameterSpec)algorithmParameterSpec;

				if (oaepSpec.getMGFAlgorithm().Equals(OAEPParameterSpec.DEFAULT.getMGFAlgorithm()))
				{
					if (oaepSpec.getPSource() is PSource.PSpecified)
					{
						return new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_RSAES_OAEP, new RSAESOAEPparams(getDigest(oaepSpec.getDigestAlgorithm()), new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_mgf1, getDigest(((MGF1ParameterSpec)oaepSpec.getMGFParameters()).getDigestAlgorithm())), new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_pSpecified, new DEROctetString(((PSource.PSpecified)oaepSpec.getPSource()).getValue()))));
					}
					else
					{
						throw new IllegalArgumentException("unknown PSource: " + oaepSpec.getPSource().getAlgorithm());
					}
				}
				else
				{
					throw new IllegalArgumentException("unknown MGF: " + oaepSpec.getMGFAlgorithm());
				}
			}

			throw new IllegalArgumentException("unknown spec: " + algorithmParameterSpec.GetType().getName());
		}

		private static readonly Map digests = new HashMap();


		private static AlgorithmIdentifier getDigest(string digest)
		{
			AlgorithmIdentifier algId = (AlgorithmIdentifier)digests.get(digest);

			if (algId != null)
			{
				return algId;
			}

			throw new IllegalArgumentException("unknown digest name: " + digest);
		}
	}

}