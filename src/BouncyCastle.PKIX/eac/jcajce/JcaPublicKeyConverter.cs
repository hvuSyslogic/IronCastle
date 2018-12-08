using org.bouncycastle.asn1.eac;

namespace org.bouncycastle.eac.jcajce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using ECDSAPublicKey = org.bouncycastle.asn1.eac.ECDSAPublicKey;
	using PublicKeyDataObject = org.bouncycastle.asn1.eac.PublicKeyDataObject;
	using RSAPublicKey = org.bouncycastle.asn1.eac.RSAPublicKey;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using FiniteField = org.bouncycastle.math.field.FiniteField;
	using Polynomial = org.bouncycastle.math.field.Polynomial;
	using PolynomialExtensionField = org.bouncycastle.math.field.PolynomialExtensionField;
	using Arrays = org.bouncycastle.util.Arrays;

	public class JcaPublicKeyConverter
	{
		private EACHelper helper = new DefaultEACHelper();

		public virtual JcaPublicKeyConverter setProvider(string providerName)
		{
			this.helper = new NamedEACHelper(providerName);

			return this;
		}

		public virtual JcaPublicKeyConverter setProvider(Provider provider)
		{
			this.helper = new ProviderEACHelper(provider);

			return this;
		}

		public virtual PublicKey getKey(PublicKeyDataObject publicKeyDataObject)
		{
			if (publicKeyDataObject.getUsage().on(EACObjectIdentifiers_Fields.id_TA_ECDSA))
			{
				return getECPublicKeyPublicKey((ECDSAPublicKey)publicKeyDataObject);
			}
			else
			{
				RSAPublicKey pubKey = (RSAPublicKey)publicKeyDataObject;
				RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(pubKey.getModulus(), pubKey.getPublicExponent());

				try
				{
					KeyFactory factk = helper.createKeyFactory("RSA");

					return factk.generatePublic(pubKeySpec);
				}
				catch (NoSuchProviderException e)
				{
					throw new EACException("cannot find provider: " + e.Message, e);
				}
				catch (NoSuchAlgorithmException e)
				{
					throw new EACException("cannot find algorithm ECDSA: " + e.Message, e);
				}
			}
		}

		private PublicKey getECPublicKeyPublicKey(ECDSAPublicKey key)
		{
			ECParameterSpec spec = getParams(key);
			java.security.spec.ECPoint publicPoint = getPublicPoint(key);
			ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(publicPoint, spec);

			KeyFactory factk;
			try
			{
				factk = helper.createKeyFactory("ECDSA");
			}
			catch (NoSuchProviderException e)
			{
				throw new EACException("cannot find provider: " + e.Message, e);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new EACException("cannot find algorithm ECDSA: " + e.Message, e);
			}

			return factk.generatePublic(pubKeySpec);
		}

		private java.security.spec.ECPoint getPublicPoint(ECDSAPublicKey key)
		{
			if (!key.hasParameters())
			{
				throw new IllegalArgumentException("Public key does not contains EC Params");
			}

			BigInteger p = key.getPrimeModulusP();
			ECCurve.Fp curve = new ECCurve.Fp(p, key.getFirstCoefA(), key.getSecondCoefB(), key.getOrderOfBasePointR(), key.getCofactorF());

			ECPoint.Fp pubY = (ECPoint.Fp)curve.decodePoint(key.getPublicPointY());

			return new java.security.spec.ECPoint(pubY.getAffineXCoord().toBigInteger(), pubY.getAffineYCoord().toBigInteger());
		}

		private ECParameterSpec getParams(ECDSAPublicKey key)
		{
			if (!key.hasParameters())
			{
				throw new IllegalArgumentException("Public key does not contains EC Params");
			}

			BigInteger p = key.getPrimeModulusP();
			ECCurve.Fp curve = new ECCurve.Fp(p, key.getFirstCoefA(), key.getSecondCoefB(), key.getOrderOfBasePointR(), key.getCofactorF());

			ECPoint G = curve.decodePoint(key.getBasePointG());

			BigInteger order = key.getOrderOfBasePointR();
			BigInteger coFactor = key.getCofactorF();

			EllipticCurve jcaCurve = convertCurve(curve);

			return new ECParameterSpec(jcaCurve, new java.security.spec.ECPoint(G.getAffineXCoord().toBigInteger(), G.getAffineYCoord().toBigInteger()), order, coFactor.intValue());
		}

		public virtual PublicKeyDataObject getPublicKeyDataObject(ASN1ObjectIdentifier usage, PublicKey publicKey)
		{
			if (publicKey is java.security.interfaces.RSAPublicKey)
			{
				java.security.interfaces.RSAPublicKey pubKey = (java.security.interfaces.RSAPublicKey)publicKey;

				return new RSAPublicKey(usage, pubKey.getModulus(), pubKey.getPublicExponent());
			}
			else
			{
				ECPublicKey pubKey = (ECPublicKey)publicKey;
				ECParameterSpec @params = pubKey.getParams();

				return new ECDSAPublicKey(usage, ((ECFieldFp)@params.getCurve().getField()).getP(), @params.getCurve().getA(), @params.getCurve().getB(), convertPoint(convertCurve(@params.getCurve(), @params.getOrder(), @params.getCofactor()), @params.getGenerator()).getEncoded(), @params.getOrder(), convertPoint(convertCurve(@params.getCurve(), @params.getOrder(), @params.getCofactor()), pubKey.getW()).getEncoded(), @params.getCofactor());
			}
		}

		private static ECPoint convertPoint(ECCurve curve, java.security.spec.ECPoint point)
		{
			return curve.createPoint(point.getAffineX(), point.getAffineY());
		}

		private static ECCurve convertCurve(EllipticCurve ec, BigInteger order, int coFactor)
		{
			ECField field = ec.getField();
			BigInteger a = ec.getA();
			BigInteger b = ec.getB();

			if (field is ECFieldFp)
			{
				return new ECCurve.Fp(((ECFieldFp)field).getP(), a, b, order, BigInteger.valueOf(coFactor));
			}
			else
			{
				throw new IllegalStateException("not implemented yet!!!");
			}
		}

		private static EllipticCurve convertCurve(ECCurve curve)
		{
			ECField field = convertField(curve.getField());
			BigInteger a = curve.getA().toBigInteger(), b = curve.getB().toBigInteger();

			// TODO: the Sun EC implementation doesn't currently handle the seed properly
			// so at the moment it's set to null. Should probably look at making this configurable
			return new EllipticCurve(field, a, b, null);
		}

		private static ECField convertField(FiniteField field)
		{
			if (ECAlgorithms.isFpField(field))
			{
				return new ECFieldFp(field.getCharacteristic());
			}
			else //if (ECAlgorithms.isF2mField(curveField))
			{
				Polynomial poly = ((PolynomialExtensionField)field).getMinimalPolynomial();
				int[] exponents = poly.getExponentsPresent();
				int[] ks = Arrays.reverse(Arrays.copyOfRange(exponents, 1, exponents.Length - 1));
				return new ECFieldF2m(poly.getDegree(), ks);
			}
		}
	}

}