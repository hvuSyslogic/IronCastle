using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ECDHPublicBCPGKey = org.bouncycastle.bcpg.ECDHPublicBCPGKey;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	public class JcePublicKeyDataDecryptorFactoryBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private OperatorHelper contentHelper = new OperatorHelper(new DefaultJcaJceHelper());
		private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();
		private JcaKeyFingerprintCalculator fingerprintCalculator = new JcaKeyFingerprintCalculator();

		public JcePublicKeyDataDecryptorFactoryBuilder()
		{
		}

		/// <summary>
		/// Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
		/// </summary>
		/// <param name="provider">  provider object for cryptographic primitives. </param>
		/// <returns>  the current builder. </returns>
		public virtual JcePublicKeyDataDecryptorFactoryBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
			keyConverter.setProvider(provider);
			this.contentHelper = helper;

			return this;
		}

		/// <summary>
		/// Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
		/// </summary>
		/// <param name="providerName">  the name of the provider to reference for cryptographic primitives. </param>
		/// <returns>  the current builder. </returns>
		public virtual JcePublicKeyDataDecryptorFactoryBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
			keyConverter.setProvider(providerName);
			this.contentHelper = helper;

			return this;
		}

		public virtual JcePublicKeyDataDecryptorFactoryBuilder setContentProvider(Provider provider)
		{
			this.contentHelper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JcePublicKeyDataDecryptorFactoryBuilder setContentProvider(string providerName)
		{
			this.contentHelper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory build(final java.security.PrivateKey privKey)
		public virtual PublicKeyDataDecryptorFactory build(PrivateKey privKey)
		{
			 return new PublicKeyDataDecryptorFactoryAnonymousInnerClass(this, privKey);
		}

		public class PublicKeyDataDecryptorFactoryAnonymousInnerClass : PublicKeyDataDecryptorFactory
		{
			private readonly JcePublicKeyDataDecryptorFactoryBuilder outerInstance;

			private PrivateKey privKey;

			public PublicKeyDataDecryptorFactoryAnonymousInnerClass(JcePublicKeyDataDecryptorFactoryBuilder outerInstance, PrivateKey privKey)
			{
				this.outerInstance = outerInstance;
				this.privKey = privKey;
			}

			public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
			{
				if (keyAlgorithm == PublicKeyAlgorithmTags_Fields.ECDH)
				{
					throw new PGPException("ECDH requires use of PGPPrivateKey for decryption");
				}
				return outerInstance.decryptSessionData(keyAlgorithm, privKey, secKeyData);
			}

			public PGPDataDecryptor createDataDecryptor(bool withIntegrityPacket, int encAlgorithm, byte[] key)
			{
				return outerInstance.contentHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory build(final org.bouncycastle.openpgp.PGPPrivateKey privKey)
		public virtual PublicKeyDataDecryptorFactory build(PGPPrivateKey privKey)
		{
			 return new PublicKeyDataDecryptorFactoryAnonymousInnerClass2(this, privKey);
		}

		public class PublicKeyDataDecryptorFactoryAnonymousInnerClass2 : PublicKeyDataDecryptorFactory
		{
			private readonly JcePublicKeyDataDecryptorFactoryBuilder outerInstance;

			private PGPPrivateKey privKey;

			public PublicKeyDataDecryptorFactoryAnonymousInnerClass2(JcePublicKeyDataDecryptorFactoryBuilder outerInstance, PGPPrivateKey privKey)
			{
				this.outerInstance = outerInstance;
				this.privKey = privKey;
			}

			public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
			{
				if (keyAlgorithm == PublicKeyAlgorithmTags_Fields.ECDH)
				{
					return outerInstance.decryptSessionData(outerInstance.keyConverter, privKey, secKeyData);
				}

				return outerInstance.decryptSessionData(keyAlgorithm, outerInstance.keyConverter.getPrivateKey(privKey), secKeyData);
			}

			public PGPDataDecryptor createDataDecryptor(bool withIntegrityPacket, int encAlgorithm, byte[] key)
			{
				return outerInstance.contentHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
			}
		}

		private byte[] decryptSessionData(JcaPGPKeyConverter converter, PGPPrivateKey privKey, byte[][] secKeyData)
		{
			PublicKeyPacket pubKeyData = privKey.getPublicKeyPacket();
			ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKeyData.getKey();
			X9ECParameters x9Params = ECNamedCurveTable.getByOID(ecKey.getCurveOID());

			byte[] enc = secKeyData[0];

			int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
			byte[] pEnc = new byte[pLen];

			JavaSystem.arraycopy(enc, 2, pEnc, 0, pLen);

			byte[] keyEnc = new byte[enc[pLen + 2]];

			JavaSystem.arraycopy(enc, 2 + pLen + 1, keyEnc, 0, keyEnc.Length);

			ECPoint publicPoint = x9Params.getCurve().decodePoint(pEnc);

			try
			{
				byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyData, fingerprintCalculator);

				KeyAgreement agreement = helper.createKeyAgreement(RFC6637Utils.getAgreementAlgorithm(pubKeyData));

				PrivateKey privateKey = converter.getPrivateKey(privKey);

				agreement.init(privateKey, new UserKeyingMaterialSpec(userKeyingMaterial));

				agreement.doPhase(converter.getPublicKey(new PGPPublicKey(new PublicKeyPacket(PublicKeyAlgorithmTags_Fields.ECDH, DateTime.Now, new ECDHPublicBCPGKey(ecKey.getCurveOID(), publicPoint, ecKey.getHashAlgorithm(), ecKey.getSymmetricKeyAlgorithm())), fingerprintCalculator)), true);

				Key key = agreement.generateSecret(RFC6637Utils.getKeyEncryptionOID(ecKey.getSymmetricKeyAlgorithm()).getId());

				Cipher c = helper.createKeyWrapper(ecKey.getSymmetricKeyAlgorithm());

				c.init(Cipher.UNWRAP_MODE, key);

				Key paddedSessionKey = c.unwrap(keyEnc, "Session", Cipher.SECRET_KEY);

				return PGPPad.unpadSessionData(paddedSessionKey.getEncoded());
			}
			catch (InvalidKeyException e)
			{
				throw new PGPException("error setting asymmetric cipher", e);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new PGPException("error setting asymmetric cipher", e);
			}
			catch (InvalidAlgorithmParameterException e)
			{
				throw new PGPException("error setting asymmetric cipher", e);
			}
			catch (GeneralSecurityException e)
			{
				throw new PGPException("error setting asymmetric cipher", e);
			}
			catch (IOException e)
			{
				throw new PGPException("error setting asymmetric cipher", e);
			}
		}

		private byte[] decryptSessionData(int keyAlgorithm, PrivateKey privKey, byte[][] secKeyData)
		{
			Cipher c1 = helper.createPublicKeyCipher(keyAlgorithm);

			try
			{
				c1.init(Cipher.DECRYPT_MODE, privKey);
			}
			catch (InvalidKeyException e)
			{
				throw new PGPException("error setting asymmetric cipher", e);
			}

			if (keyAlgorithm == PGPPublicKey.RSA_ENCRYPT || keyAlgorithm == PGPPublicKey.RSA_GENERAL)
			{
				byte[] bi = secKeyData[0]; // encoded MPI

				c1.update(bi, 2, bi.Length - 2);
			}
			else
			{
				DHKey k = (DHKey)privKey;
				int size = (k.getParams().getP().bitLength() + 7) / 8;
				byte[] tmp = new byte[size];

				byte[] bi = secKeyData[0]; // encoded MPI
				if (bi.Length - 2 > size) // leading Zero? Shouldn't happen but...
				{
					c1.update(bi, 3, bi.Length - 3);
				}
				else
				{
					JavaSystem.arraycopy(bi, 2, tmp, tmp.Length - (bi.Length - 2), bi.Length - 2);
					c1.update(tmp);
				}

				bi = secKeyData[1]; // encoded MPI
				for (int i = 0; i != tmp.Length; i++)
				{
					tmp[i] = 0;
				}

				if (bi.Length - 2 > size) // leading Zero? Shouldn't happen but...
				{
					c1.update(bi, 3, bi.Length - 3);
				}
				else
				{
					JavaSystem.arraycopy(bi, 2, tmp, tmp.Length - (bi.Length - 2), bi.Length - 2);
					c1.update(tmp);
				}
			}

			try
			{
				return c1.doFinal();
			}
			catch (Exception e)
			{
				throw new PGPException("exception decrypting session data", e);
			}
		}
	}

}