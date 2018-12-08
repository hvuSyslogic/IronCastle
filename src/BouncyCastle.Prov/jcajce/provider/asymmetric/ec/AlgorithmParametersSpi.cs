using org.bouncycastle.jce.spec;

namespace org.bouncycastle.jcajce.provider.asymmetric.ec
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	public class AlgorithmParametersSpi : java.security.AlgorithmParametersSpi
	{
		private ECParameterSpec ecParameterSpec;
		private string curveName;

		public virtual bool isASN1FormatString(string format)
		{
			return string.ReferenceEquals(format, null) || format.Equals("ASN.1");
		}

		public override void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
		{
			if (algorithmParameterSpec is ECGenParameterSpec)
			{
				ECGenParameterSpec ecGenParameterSpec = (ECGenParameterSpec)algorithmParameterSpec;
				X9ECParameters @params = ECUtils.getDomainParametersFromGenSpec(ecGenParameterSpec);

				if (@params == null)
				{
					throw new InvalidParameterSpecException("EC curve name not recognized: " + ecGenParameterSpec.getName());
				}
				curveName = ecGenParameterSpec.getName();
				ECParameterSpec baseSpec = EC5Util.convertToSpec(@params);
				ecParameterSpec = new ECNamedCurveSpec(curveName, baseSpec.getCurve(), baseSpec.getGenerator(), baseSpec.getOrder(), BigInteger.valueOf(baseSpec.getCofactor()));
			}
			else if (algorithmParameterSpec is ECParameterSpec)
			{
				if (algorithmParameterSpec is ECNamedCurveSpec)
				{
					curveName = ((ECNamedCurveSpec)algorithmParameterSpec).getName();
				}
				else
				{
					curveName = null;
				}
				ecParameterSpec = (ECParameterSpec)algorithmParameterSpec;
			}
			else
			{
				throw new InvalidParameterSpecException("AlgorithmParameterSpec class not recognized: " + algorithmParameterSpec.GetType().getName());
			}
		}

		public override void engineInit(byte[] bytes)
		{
			engineInit(bytes, "ASN.1");
		}

		public override void engineInit(byte[] bytes, string format)
		{
			if (isASN1FormatString(format))
			{
				X962Parameters @params = X962Parameters.getInstance(bytes);

				ECCurve curve = EC5Util.getCurve(BouncyCastleProvider.CONFIGURATION, @params);

				if (@params.isNamedCurve())
				{
					ASN1ObjectIdentifier curveId = ASN1ObjectIdentifier.getInstance(@params.getParameters());

					curveName = ECNamedCurveTable.getName(curveId);
					if (string.ReferenceEquals(curveName, null))
					{
						curveName = curveId.getId();
					}
				}

				ecParameterSpec = EC5Util.convertToSpec(@params, curve);
			}
			else
			{
				throw new IOException("Unknown encoded parameters format in AlgorithmParameters object: " + format);
			}
		}

		public override T engineGetParameterSpec<T>(Class<T> paramSpec) where T : java.security.spec.AlgorithmParameterSpec
		{
			if (typeof(ECParameterSpec).isAssignableFrom(paramSpec) || paramSpec == typeof(AlgorithmParameterSpec))
			{
				return (T)ecParameterSpec;
			}
			else if (typeof(ECGenParameterSpec).isAssignableFrom(paramSpec))
			{
				if (!string.ReferenceEquals(curveName, null))
				{
					ASN1ObjectIdentifier namedCurveOid = ECUtil.getNamedCurveOid(curveName);

					if (namedCurveOid != null)
					{
						return (T)new ECGenParameterSpec(namedCurveOid.getId());
					}
					return (T)new ECGenParameterSpec(curveName);
				}
				else
				{
					ASN1ObjectIdentifier namedCurveOid = ECUtil.getNamedCurveOid(EC5Util.convertSpec(ecParameterSpec, false));

					if (namedCurveOid != null)
					{
						return (T)new ECGenParameterSpec(namedCurveOid.getId());
					}
				}
			}
			throw new InvalidParameterSpecException("EC AlgorithmParameters cannot convert to " + paramSpec.getName());
		}

		public override byte[] engineGetEncoded()
		{
			return engineGetEncoded("ASN.1");
		}

		public override byte[] engineGetEncoded(string format)
		{
			if (isASN1FormatString(format))
			{
				X962Parameters @params;

				if (ecParameterSpec == null) // implicitly CA
				{
					@params = new X962Parameters(DERNull.INSTANCE);
				}
				else if (!string.ReferenceEquals(curveName, null))
				{
					@params = new X962Parameters(ECUtil.getNamedCurveOid(curveName));
				}
				else
				{
					ECParameterSpec ecSpec = EC5Util.convertSpec(ecParameterSpec, false);
					X9ECParameters ecP = new X9ECParameters(ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN(), ecSpec.getH(), ecSpec.getSeed());

					@params = new X962Parameters(ecP);
				}

				return @params.getEncoded();
			}

			throw new IOException("Unknown parameters format in AlgorithmParameters object: " + format);
		}

		public override string engineToString()
		{
			return "EC AlgorithmParameters ";
		}
	}

}