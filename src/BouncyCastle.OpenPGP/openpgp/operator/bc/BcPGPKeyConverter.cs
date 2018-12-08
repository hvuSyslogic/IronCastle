using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.@operator.bc
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
	using ECPublicBCPGKey = org.bouncycastle.bcpg.ECPublicBCPGKey;
	using ECSecretBCPGKey = org.bouncycastle.bcpg.ECSecretBCPGKey;
	using ElGamalPublicBCPGKey = org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
	using ElGamalSecretBCPGKey = org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using RSAPublicBCPGKey = org.bouncycastle.bcpg.RSAPublicBCPGKey;
	using RSASecretBCPGKey = org.bouncycastle.bcpg.RSASecretBCPGKey;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPrivateKeyParameters = org.bouncycastle.crypto.@params.DSAPrivateKeyParameters;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using ECNamedDomainParameters = org.bouncycastle.crypto.@params.ECNamedDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ElGamalParameters = org.bouncycastle.crypto.@params.ElGamalParameters;
	using ElGamalPrivateKeyParameters = org.bouncycastle.crypto.@params.ElGamalPrivateKeyParameters;
	using ElGamalPublicKeyParameters = org.bouncycastle.crypto.@params.ElGamalPublicKeyParameters;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using SubjectPublicKeyInfoFactory = org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

	public class BcPGPKeyConverter
	{
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
		public virtual PGPPublicKey getPGPPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, AsymmetricKeyParameter pubKey, DateTime time)
		{
			BCPGKey bcpgKey;

			if (pubKey is RSAKeyParameters)
			{
				RSAKeyParameters rK = (RSAKeyParameters)pubKey;

				bcpgKey = new RSAPublicBCPGKey(rK.getModulus(), rK.getExponent());
			}
			else if (pubKey is DSAPublicKeyParameters)
			{
				DSAPublicKeyParameters dK = (DSAPublicKeyParameters)pubKey;
				DSAParameters dP = dK.getParameters();

				bcpgKey = new DSAPublicBCPGKey(dP.getP(), dP.getQ(), dP.getG(), dK.getY());
			}
			else if (pubKey is ElGamalPublicKeyParameters)
			{
				ElGamalPublicKeyParameters eK = (ElGamalPublicKeyParameters)pubKey;
				ElGamalParameters eS = eK.getParameters();

				bcpgKey = new ElGamalPublicBCPGKey(eS.getP(), eS.getG(), eK.getY());
			}
			else if (pubKey is ECPublicKeyParameters)
			{
				SubjectPublicKeyInfo keyInfo;
				try
				{
					keyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pubKey);
				}
				catch (IOException e)
				{
					throw new PGPException("Unable to encode key: " + e.Message, e);
				}

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

			return new PGPPublicKey(new PublicKeyPacket(algorithm, time, bcpgKey), new BcKeyFingerprintCalculator());
		}

		public virtual PGPPrivateKey getPGPPrivateKey(PGPPublicKey pubKey, AsymmetricKeyParameter privKey)
		{
			BCPGKey privPk;

			switch (pubKey.getAlgorithm())
			{
			case PGPPublicKey.RSA_ENCRYPT:
			case PGPPublicKey.RSA_SIGN:
			case PGPPublicKey.RSA_GENERAL:
				RSAPrivateCrtKeyParameters rsK = (RSAPrivateCrtKeyParameters)privKey;

				privPk = new RSASecretBCPGKey(rsK.getExponent(), rsK.getP(), rsK.getQ());
				break;
			case PGPPublicKey.DSA:
				DSAPrivateKeyParameters dsK = (DSAPrivateKeyParameters)privKey;

				privPk = new DSASecretBCPGKey(dsK.getX());
				break;
			case PGPPublicKey.ELGAMAL_ENCRYPT:
			case PGPPublicKey.ELGAMAL_GENERAL:
				ElGamalPrivateKeyParameters esK = (ElGamalPrivateKeyParameters)privKey;

				privPk = new ElGamalSecretBCPGKey(esK.getX());
				break;
			case PGPPublicKey.ECDH:
			case PGPPublicKey.ECDSA:
				ECPrivateKeyParameters ecK = (ECPrivateKeyParameters)privKey;

				privPk = new ECSecretBCPGKey(ecK.getD());
				break;
			default:
				throw new PGPException("unknown key class");
			}
			return new PGPPrivateKey(pubKey.getKeyID(), pubKey.getPublicKeyPacket(), privPk);
		}

		public virtual AsymmetricKeyParameter getPublicKey(PGPPublicKey publicKey)
		{
			PublicKeyPacket publicPk = publicKey.getPublicKeyPacket();

			try
			{
				switch (publicPk.getAlgorithm())
				{
				case PublicKeyAlgorithmTags_Fields.RSA_ENCRYPT:
				case PublicKeyAlgorithmTags_Fields.RSA_GENERAL:
				case PublicKeyAlgorithmTags_Fields.RSA_SIGN:
					RSAPublicBCPGKey rsaK = (RSAPublicBCPGKey)publicPk.getKey();

					return new RSAKeyParameters(false, rsaK.getModulus(), rsaK.getPublicExponent());
				case PublicKeyAlgorithmTags_Fields.DSA:
					DSAPublicBCPGKey dsaK = (DSAPublicBCPGKey)publicPk.getKey();

					return new DSAPublicKeyParameters(dsaK.getY(), new DSAParameters(dsaK.getP(), dsaK.getQ(), dsaK.getG()));
				case PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT:
				case PublicKeyAlgorithmTags_Fields.ELGAMAL_GENERAL:
					ElGamalPublicBCPGKey elK = (ElGamalPublicBCPGKey)publicPk.getKey();

					return new ElGamalPublicKeyParameters(elK.getY(), new ElGamalParameters(elK.getP(), elK.getG()));
				case PGPPublicKey.ECDH:
				case PGPPublicKey.ECDSA:
					ECPublicBCPGKey ecPub = (ECPublicBCPGKey)publicPk.getKey();
					X9ECParameters x9 = BcUtil.getX9Parameters(ecPub.getCurveOID());

					return new ECPublicKeyParameters(BcUtil.decodePoint(ecPub.getEncodedPoint(), x9.getCurve()), new ECNamedDomainParameters(ecPub.getCurveOID(), x9.getCurve(), x9.getG(), x9.getN(), x9.getH()));
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

		public virtual AsymmetricKeyParameter getPrivateKey(PGPPrivateKey privKey)
		{
			PublicKeyPacket pubPk = privKey.getPublicKeyPacket();
			BCPGKey privPk = privKey.getPrivateKeyDataPacket();

			try
			{
				switch (pubPk.getAlgorithm())
				{
				case PGPPublicKey.RSA_ENCRYPT:
				case PGPPublicKey.RSA_GENERAL:
				case PGPPublicKey.RSA_SIGN:
					RSAPublicBCPGKey rsaPub = (RSAPublicBCPGKey)pubPk.getKey();
					RSASecretBCPGKey rsaPriv = (RSASecretBCPGKey)privPk;

					return new RSAPrivateCrtKeyParameters(rsaPriv.getModulus(), rsaPub.getPublicExponent(), rsaPriv.getPrivateExponent(), rsaPriv.getPrimeP(), rsaPriv.getPrimeQ(), rsaPriv.getPrimeExponentP(), rsaPriv.getPrimeExponentQ(), rsaPriv.getCrtCoefficient());
				case PGPPublicKey.DSA:
					DSAPublicBCPGKey dsaPub = (DSAPublicBCPGKey)pubPk.getKey();
					DSASecretBCPGKey dsaPriv = (DSASecretBCPGKey)privPk;

					return new DSAPrivateKeyParameters(dsaPriv.getX(), new DSAParameters(dsaPub.getP(), dsaPub.getQ(), dsaPub.getG()));
				case PGPPublicKey.ELGAMAL_ENCRYPT:
				case PGPPublicKey.ELGAMAL_GENERAL:
					ElGamalPublicBCPGKey elPub = (ElGamalPublicBCPGKey)pubPk.getKey();
					ElGamalSecretBCPGKey elPriv = (ElGamalSecretBCPGKey)privPk;

					return new ElGamalPrivateKeyParameters(elPriv.getX(), new ElGamalParameters(elPub.getP(), elPub.getG()));
				case PGPPublicKey.ECDH:
				case PGPPublicKey.ECDSA:
					ECPublicBCPGKey ecPub = (ECPublicBCPGKey)pubPk.getKey();
					ECSecretBCPGKey ecPriv = (ECSecretBCPGKey)privPk;

					X9ECParameters x9 = BcUtil.getX9Parameters(ecPub.getCurveOID());

					return new ECPrivateKeyParameters(ecPriv.getX(), new ECNamedDomainParameters(ecPub.getCurveOID(), x9.getCurve(), x9.getG(), x9.getN(), x9.getH()));
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
	}

}