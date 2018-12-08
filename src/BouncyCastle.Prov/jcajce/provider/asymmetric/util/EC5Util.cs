using org.bouncycastle.jce.spec;
using org.bouncycastle.math.ec;

namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using FiniteField = org.bouncycastle.math.field.FiniteField;
	using Polynomial = org.bouncycastle.math.field.Polynomial;
	using PolynomialExtensionField = org.bouncycastle.math.field.PolynomialExtensionField;
	using Arrays = org.bouncycastle.util.Arrays;

	public class EC5Util
	{
		private static Map customCurves = new HashMap();

		static EC5Util()
		{
			Enumeration e = CustomNamedCurves.getNames();
			while (e.hasMoreElements())
			{
				string name = (string)e.nextElement();

				X9ECParameters curveParams = ECNamedCurveTable.getByName(name);
				if (curveParams != null) // there may not be a regular curve, may just be a custom curve.
				{
					customCurves.put(curveParams.getCurve(), CustomNamedCurves.getByName(name).getCurve());
				}
			}

			X9ECParameters x9_25519 = CustomNamedCurves.getByName("Curve25519");
			ECCurve c_25519 = x9_25519.getCurve();

			customCurves.put(new ECCurve.Fp(c_25519.getField().getCharacteristic(), c_25519.getA().toBigInteger(), c_25519.getB().toBigInteger(), c_25519.getOrder(), c_25519.getCofactor()), c_25519);
		}

		public static ECCurve getCurve(ProviderConfiguration configuration, X962Parameters @params)
		{
			ECCurve curve;
			Set acceptableCurves = configuration.getAcceptableNamedCurves();

			if (@params.isNamedCurve())
			{
				ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(@params.getParameters());

				if (acceptableCurves.isEmpty() || acceptableCurves.contains(oid))
				{
					X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);

					if (ecP == null)
					{
						ecP = (X9ECParameters)configuration.getAdditionalECParameters().get(oid);
					}

					curve = ecP.getCurve();
				}
				else
				{
					throw new IllegalStateException("named curve not acceptable");
				}
			}
			else if (@params.isImplicitlyCA())
			{
				curve = configuration.getEcImplicitlyCa().getCurve();
			}
			else if (acceptableCurves.isEmpty())
			{
				X9ECParameters ecP = X9ECParameters.getInstance(@params.getParameters());

				curve = ecP.getCurve();
			}
			else
			{
				throw new IllegalStateException("encoded parameters not acceptable");
			}

			return curve;
		}

		public static ECDomainParameters getDomainParameters(ProviderConfiguration configuration, ECParameterSpec @params)
		{
			ECDomainParameters domainParameters;

			if (@params == null)
			{
				ECParameterSpec iSpec = configuration.getEcImplicitlyCa();

				domainParameters = new ECDomainParameters(iSpec.getCurve(), iSpec.getG(), iSpec.getN(), iSpec.getH(), iSpec.getSeed());
			}
			else
			{
				domainParameters = ECUtil.getDomainParameters(configuration, convertSpec(@params, false));
			}

			return domainParameters;
		}

		public static ECParameterSpec convertToSpec(X962Parameters @params, ECCurve curve)
		{
			ECParameterSpec ecSpec;
			EllipticCurve ellipticCurve;

			if (@params.isNamedCurve())
			{
				ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)@params.getParameters();
				X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);
				if (ecP == null)
				{
					Map additionalECParameters = BouncyCastleProvider.CONFIGURATION.getAdditionalECParameters();
					if (!additionalECParameters.isEmpty())
					{
						ecP = (X9ECParameters)additionalECParameters.get(oid);
					}
				}

				ellipticCurve = EC5Util.convertCurve(curve, ecP.getSeed());

				ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(oid), ellipticCurve, convertPoint(ecP.getG()), ecP.getN(), ecP.getH());
			}
			else if (@params.isImplicitlyCA())
			{
				ecSpec = null;
			}
			else
			{
				X9ECParameters ecP = X9ECParameters.getInstance(@params.getParameters());

				ellipticCurve = EC5Util.convertCurve(curve, ecP.getSeed());

				if (ecP.getH() != null)
				{
					ecSpec = new ECParameterSpec(ellipticCurve, convertPoint(ecP.getG()), ecP.getN(), ecP.getH().intValue());
				}
				else
				{
					ecSpec = new ECParameterSpec(ellipticCurve, convertPoint(ecP.getG()), ecP.getN(), 1); // TODO: not strictly correct... need to fix the test data...
				}
			}

			return ecSpec;
		}

		public static ECParameterSpec convertToSpec(X9ECParameters domainParameters)
		{
			return new ECParameterSpec(convertCurve(domainParameters.getCurve(), null), EC5Util.convertPoint(domainParameters.getG()), domainParameters.getN(), domainParameters.getH().intValue());
		}

		public static ECParameterSpec convertToSpec(ECDomainParameters domainParameters)
		{
			return new ECParameterSpec(convertCurve(domainParameters.getCurve(), null), EC5Util.convertPoint(domainParameters.getG()), domainParameters.getN(), domainParameters.getH().intValue());
		}

		public static EllipticCurve convertCurve(ECCurve curve, byte[] seed)
		{
			ECField field = convertField(curve.getField());
			BigInteger a = curve.getA().toBigInteger(), b = curve.getB().toBigInteger();

			// TODO: the Sun EC implementation doesn't currently handle the seed properly
			// so at the moment it's set to null. Should probably look at making this configurable
			return new EllipticCurve(field, a, b, null);
		}

		public static ECCurve convertCurve(EllipticCurve ec)
		{
			ECField field = ec.getField();
			BigInteger a = ec.getA();
			BigInteger b = ec.getB();

			if (field is ECFieldFp)
			{
				ECCurve.Fp curve = new ECCurve.Fp(((ECFieldFp)field).getP(), a, b);

				if (customCurves.containsKey(curve))
				{
					return (ECCurve)customCurves.get(curve);
				}

				return curve;
			}
			else
			{
				ECFieldF2m fieldF2m = (ECFieldF2m)field;
				int m = fieldF2m.getM();
				int[] ks = ECUtil.convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
				return new ECCurve.F2m(m, ks[0], ks[1], ks[2], a, b);
			}
		}

		public static ECField convertField(FiniteField field)
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

		public static ECParameterSpec convertSpec(EllipticCurve ellipticCurve, ECParameterSpec spec)
		{
			if (spec is ECNamedCurveParameterSpec)
			{
				return new ECNamedCurveSpec(((ECNamedCurveParameterSpec)spec).getName(), ellipticCurve, convertPoint(spec.getG()), spec.getN(), spec.getH());
			}
			else
			{
				return new ECParameterSpec(ellipticCurve, convertPoint(spec.getG()), spec.getN(), spec.getH().intValue());
			}
		}

		public static ECParameterSpec convertSpec(ECParameterSpec ecSpec, bool withCompression)
		{
			ECCurve curve = convertCurve(ecSpec.getCurve());

			if (ecSpec is ECNamedCurveSpec)
			{
				return new ECNamedCurveParameterSpec(((ECNamedCurveSpec)ecSpec).getName(), curve, convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());
			}
			else
			{
				return new ECParameterSpec(curve, convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());
			}
		}

		public static ECPoint convertPoint(ECParameterSpec ecSpec, ECPoint point, bool withCompression)
		{
			return convertPoint(convertCurve(ecSpec.getCurve()), point, withCompression);
		}

		public static ECPoint convertPoint(ECCurve curve, ECPoint point, bool withCompression)
		{
			return curve.createPoint(point.getAffineX(), point.getAffineY());
		}

		public static ECPoint convertPoint(ECPoint point)
		{
			point = point.normalize();

			return new ECPoint(point.getAffineXCoord().toBigInteger(), point.getAffineYCoord().toBigInteger());
		}
	}

}