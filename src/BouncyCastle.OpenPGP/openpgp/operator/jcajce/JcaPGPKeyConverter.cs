using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ECPoint = org.bouncycastle.asn1.x9.X9ECPoint;
	using BCPGKey = org.bouncycastle.bcpg.BCPGKey;
	using DSAPublicBCPGKey = org.bouncycastle.bcpg.DSAPublicBCPGKey;
	using DSASecretBCPGKey = org.bouncycastle.bcpg.DSASecretBCPGKey;
	using ECDHPublicBCPGKey = org.bouncycastle.bcpg.ECDHPublicBCPGKey;
	using ECDSAPublicBCPGKey = org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
	using ECSecretBCPGKey = org.bouncycastle.bcpg.ECSecretBCPGKey;
	using ElGamalPublicBCPGKey = org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
	using ElGamalSecretBCPGKey = org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using RSAPublicBCPGKey = org.bouncycastle.bcpg.RSAPublicBCPGKey;
	using RSASecretBCPGKey = org.bouncycastle.bcpg.RSASecretBCPGKey;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	public class JcaPGPKeyConverter
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private KeyFingerPrintCalculator fingerPrintCalculator = new JcaKeyFingerprintCalculator();

		public virtual JcaPGPKeyConverter setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JcaPGPKeyConverter setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual PublicKey getPublicKey(PGPPublicKey publicKey)
		{
			KeyFactory fact;

			PublicKeyPacket publicPk = publicKey.getPublicKeyPacket();

			try
			{
				switch (publicPk.getAlgorithm())
				{
				case PublicKeyAlgorithmTags_Fields.RSA_ENCRYPT:
				case PublicKeyAlgorithmTags_Fields.RSA_GENERAL:
				case PublicKeyAlgorithmTags_Fields.RSA_SIGN:
					RSAPublicBCPGKey rsaK = (RSAPublicBCPGKey)publicPk.getKey();
					RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsaK.getModulus(), rsaK.getPublicExponent());

					fact = helper.createKeyFactory("RSA");

					return fact.generatePublic(rsaSpec);
				case PublicKeyAlgorithmTags_Fields.DSA:
					DSAPublicBCPGKey dsaK = (DSAPublicBCPGKey)publicPk.getKey();
					DSAPublicKeySpec dsaSpec = new DSAPublicKeySpec(dsaK.getY(), dsaK.getP(), dsaK.getQ(), dsaK.getG());

					fact = helper.createKeyFactory("DSA");

					return fact.generatePublic(dsaSpec);
				case PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT:
				case PublicKeyAlgorithmTags_Fields.ELGAMAL_GENERAL:
					ElGamalPublicBCPGKey elK = (ElGamalPublicBCPGKey)publicPk.getKey();
					DHPublicKeySpec elSpec = new DHPublicKeySpec(elK.getY(), elK.getP(), elK.getG());

					fact = helper.createKeyFactory("ElGamal");

					return fact.generatePublic(elSpec);
				case PublicKeyAlgorithmTags_Fields.ECDH:
					ECDHPublicBCPGKey ecdhK = (ECDHPublicBCPGKey)publicPk.getKey();
					X9ECParameters ecdhParams = JcaJcePGPUtil.getX9Parameters(ecdhK.getCurveOID());
					ECPoint ecdhPoint = JcaJcePGPUtil.decodePoint(ecdhK.getEncodedPoint(), ecdhParams.getCurve());
					ECPublicKeySpec ecDhSpec = new ECPublicKeySpec(new java.security.spec.ECPoint(ecdhPoint.getAffineXCoord().toBigInteger(), ecdhPoint.getAffineYCoord().toBigInteger()), getECParameterSpec(ecdhK.getCurveOID(), ecdhParams));
					fact = helper.createKeyFactory("ECDH");

					return fact.generatePublic(ecDhSpec);
				case PublicKeyAlgorithmTags_Fields.ECDSA:
					ECDSAPublicBCPGKey ecdsaK = (ECDSAPublicBCPGKey)publicPk.getKey();
					X9ECParameters ecdsaParams = JcaJcePGPUtil.getX9Parameters(ecdsaK.getCurveOID());
					ECPoint ecdsaPoint = JcaJcePGPUtil.decodePoint(ecdsaK.getEncodedPoint(), ecdsaParams.getCurve());
					ECPublicKeySpec ecDsaSpec = new ECPublicKeySpec(new java.security.spec.ECPoint(ecdsaPoint.getAffineXCoord().toBigInteger(), ecdsaPoint.getAffineYCoord().toBigInteger()), getECParameterSpec(ecdsaK.getCurveOID(), ecdsaParams));
					fact = helper.createKeyFactory("ECDSA");

					return fact.generatePublic(ecDsaSpec);
				default:
					throw new PGPException("unknown public key algorithm encountered");
				}
			}
			catch (PGPException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new PGPException("exception constructing public key", e);
			}
		}

		/// <summary>
		/// Create a PGPPublicKey from the passed in JCA one.
		/// <para>
		/// Note: the time passed in affects the value of the key's keyID, so you probably only want
		/// to do this once for a JCA key, or make sure you keep track of the time you used.
		/// </para> </summary>
		/// <param name="algorithm"> asymmetric algorithm type representing the public key. </param>
		/// <param name="algorithmParameters"> additional parameters to be stored against the public key. </param>
		/// <param name="pubKey">    actual public key to associate. </param>
		/// <param name="time">      date of creation. </param>
		/// <exception cref="PGPException"> on key creation problem. </exception>
		public virtual PGPPublicKey getPGPPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, DateTime time)
		{
			BCPGKey bcpgKey;

			if (pubKey is RSAPublicKey)
			{
				RSAPublicKey rK = (RSAPublicKey)pubKey;

				bcpgKey = new RSAPublicBCPGKey(rK.getModulus(), rK.getPublicExponent());
			}
			else if (pubKey is DSAPublicKey)
			{
				DSAPublicKey dK = (DSAPublicKey)pubKey;
				DSAParams dP = dK.getParams();

				bcpgKey = new DSAPublicBCPGKey(dP.getP(), dP.getQ(), dP.getG(), dK.getY());
			}
			else if (pubKey is DHPublicKey)
			{
				DHPublicKey eK = (DHPublicKey)pubKey;
				DHParameterSpec eS = eK.getParams();

				bcpgKey = new ElGamalPublicBCPGKey(eS.getP(), eS.getG(), eK.getY());
			}
			else if (pubKey is ECPublicKey)
			{
				SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());

				// TODO: should probably match curve by comparison as well
				ASN1ObjectIdentifier curveOid = ASN1ObjectIdentifier.getInstance(keyInfo.getAlgorithm().getParameters());

				X9ECParameters @params = ECNamedCurveTable.getByOID(curveOid);

				ASN1OctetString key = new DEROctetString(keyInfo.getPublicKeyData().getBytes());
				X9ECPoint derQ = new X9ECPoint(@params.getCurve(), key);

				if (algorithm == PGPPublicKey.ECDH)
				{
					PGPKdfParameters kdfParams = (PGPKdfParameters)algorithmParameters;
					if (kdfParams == null)
					{
						// We default to these as they are specified as mandatory in RFC 6631.
						kdfParams = new PGPKdfParameters(HashAlgorithmTags_Fields.SHA256, SymmetricKeyAlgorithmTags_Fields.AES_128);
					}
					bcpgKey = new ECDHPublicBCPGKey(curveOid, derQ.getPoint(), kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
				}
				else if (algorithm == PGPPublicKey.ECDSA)
				{
					bcpgKey = new ECDSAPublicBCPGKey(curveOid, derQ.getPoint());
				}
				else
				{
					throw new PGPException("unknown EC algorithm");
				}
			}
			else
			{
				throw new PGPException("unknown key class");
			}

			return new PGPPublicKey(new PublicKeyPacket(algorithm, time, bcpgKey), fingerPrintCalculator);
		}

		/// <summary>
		/// Create a PGPPublicKey from the passed in JCA one.
		/// <para>
		/// Note: the time passed in affects the value of the key's keyID, so you probably only want
		/// to do this once for a JCA key, or make sure you keep track of the time you used.
		/// </para> </summary>
		/// <param name="algorithm"> asymmetric algorithm type representing the public key. </param>
		/// <param name="pubKey">    actual public key to associate. </param>
		/// <param name="time">      date of creation. </param>
		/// <exception cref="PGPException"> on key creation problem. </exception>
		public virtual PGPPublicKey getPGPPublicKey(int algorithm, PublicKey pubKey, DateTime time)
		{
			return getPGPPublicKey(algorithm, null, pubKey, time);
		}

		public virtual PrivateKey getPrivateKey(PGPPrivateKey privKey)
		{
			if (privKey is JcaPGPPrivateKey)
			{
				return ((JcaPGPPrivateKey)privKey).getPrivateKey();
			}

			PublicKeyPacket pubPk = privKey.getPublicKeyPacket();
			BCPGKey privPk = privKey.getPrivateKeyDataPacket();

			try
			{
				KeyFactory fact;

				switch (pubPk.getAlgorithm())
				{
				case PGPPublicKey.RSA_ENCRYPT:
				case PGPPublicKey.RSA_GENERAL:
				case PGPPublicKey.RSA_SIGN:
					RSAPublicBCPGKey rsaPub = (RSAPublicBCPGKey)pubPk.getKey();
					RSASecretBCPGKey rsaPriv = (RSASecretBCPGKey)privPk;
					RSAPrivateCrtKeySpec rsaPrivSpec = new RSAPrivateCrtKeySpec(rsaPriv.getModulus(), rsaPub.getPublicExponent(), rsaPriv.getPrivateExponent(), rsaPriv.getPrimeP(), rsaPriv.getPrimeQ(), rsaPriv.getPrimeExponentP(), rsaPriv.getPrimeExponentQ(), rsaPriv.getCrtCoefficient());

					fact = helper.createKeyFactory("RSA");

					return fact.generatePrivate(rsaPrivSpec);
				case PGPPublicKey.DSA:
					DSAPublicBCPGKey dsaPub = (DSAPublicBCPGKey)pubPk.getKey();
					DSASecretBCPGKey dsaPriv = (DSASecretBCPGKey)privPk;
					DSAPrivateKeySpec dsaPrivSpec = new DSAPrivateKeySpec(dsaPriv.getX(), dsaPub.getP(), dsaPub.getQ(), dsaPub.getG());

					fact = helper.createKeyFactory("DSA");

					return fact.generatePrivate(dsaPrivSpec);
				case PublicKeyAlgorithmTags_Fields.ECDH:
					ECDHPublicBCPGKey ecdhPub = (ECDHPublicBCPGKey)pubPk.getKey();
					ECSecretBCPGKey ecdhK = (ECSecretBCPGKey)privPk;
					ECPrivateKeySpec ecDhSpec = new ECPrivateKeySpec(ecdhK.getX(), getECParameterSpec(ecdhPub.getCurveOID()));
					fact = helper.createKeyFactory("ECDH");

					return fact.generatePrivate(ecDhSpec);
				case PublicKeyAlgorithmTags_Fields.ECDSA:
					ECDSAPublicBCPGKey ecdsaPub = (ECDSAPublicBCPGKey)pubPk.getKey();
					ECSecretBCPGKey ecdsaK = (ECSecretBCPGKey)privPk;
					ECPrivateKeySpec ecDsaSpec = new ECPrivateKeySpec(ecdsaK.getX(), getECParameterSpec(ecdsaPub.getCurveOID()));
					fact = helper.createKeyFactory("ECDSA");

					return fact.generatePrivate(ecDsaSpec);
				case PGPPublicKey.ELGAMAL_ENCRYPT:
				case PGPPublicKey.ELGAMAL_GENERAL:
					ElGamalPublicBCPGKey elPub = (ElGamalPublicBCPGKey)pubPk.getKey();
					ElGamalSecretBCPGKey elPriv = (ElGamalSecretBCPGKey)privPk;
					DHPrivateKeySpec elSpec = new DHPrivateKeySpec(elPriv.getX(), elPub.getP(), elPub.getG());

					fact = helper.createKeyFactory("ElGamal");

					return fact.generatePrivate(elSpec);
				default:
					throw new PGPException("unknown public key algorithm encountered");
				}
			}
			catch (PGPException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new PGPException("Exception constructing key", e);
			}
		}

		/// <summary>
		/// Convert a PrivateKey into a PGPPrivateKey.
		/// </summary>
		/// <param name="pub">   the corresponding PGPPublicKey to privKey. </param>
		/// <param name="privKey">  the private key for the key in pub. </param>
		/// <returns> a PGPPrivateKey </returns>
		/// <exception cref="PGPException"> </exception>
		public virtual PGPPrivateKey getPGPPrivateKey(PGPPublicKey pub, PrivateKey privKey)
		{
			BCPGKey privPk;

			switch (pub.getAlgorithm())
			{
			case PGPPublicKey.RSA_ENCRYPT:
			case PGPPublicKey.RSA_SIGN:
			case PGPPublicKey.RSA_GENERAL:
				RSAPrivateCrtKey rsK = (RSAPrivateCrtKey)privKey;

				privPk = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
				break;
			case PGPPublicKey.DSA:
				DSAPrivateKey dsK = (DSAPrivateKey)privKey;

				privPk = new DSASecretBCPGKey(dsK.getX());
				break;
			case PGPPublicKey.ELGAMAL_ENCRYPT:
			case PGPPublicKey.ELGAMAL_GENERAL:
				DHPrivateKey esK = (DHPrivateKey)privKey;

				privPk = new ElGamalSecretBCPGKey(esK.getX());
				break;
			case PGPPublicKey.ECDH:
			case PGPPublicKey.ECDSA:
				ECPrivateKey ecK = (ECPrivateKey)privKey;

				privPk = new ECSecretBCPGKey(ecK.getS());
				break;
			default:
				throw new PGPException("unknown key class");
			}

			return new PGPPrivateKey(pub.getKeyID(), pub.getPublicKeyPacket(), privPk);
		}

		private ECParameterSpec getECParameterSpec(ASN1ObjectIdentifier curveOid)
		{
			return getECParameterSpec(curveOid, JcaJcePGPUtil.getX9Parameters(curveOid));
		}

		private ECParameterSpec getECParameterSpec(ASN1ObjectIdentifier curveOid, X9ECParameters x9Params)
		{
			AlgorithmParameters @params = helper.createAlgorithmParameters("EC");

			@params.init(new ECGenParameterSpec(ECNamedCurveTable.getName(curveOid)));

			return @params.getParameterSpec(typeof(ECParameterSpec));
		}
	}

}