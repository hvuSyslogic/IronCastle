namespace org.bouncycastle.jcajce.provider.asymmetric.ec
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	public class ECUtils
	{
		internal static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			return (key is BCECPublicKey) ? ((BCECPublicKey)key).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(key);
		}

		internal static X9ECParameters getDomainParametersFromGenSpec(ECGenParameterSpec genSpec)
		{
			return getDomainParametersFromName(genSpec.getName());
		}

		internal static X9ECParameters getDomainParametersFromName(string curveName)
		{
			X9ECParameters domainParameters;
			try
			{
				if (curveName[0] >= '0' && curveName[0] <= '2')
				{
					ASN1ObjectIdentifier oidID = new ASN1ObjectIdentifier(curveName);
					domainParameters = ECUtil.getNamedCurveByOid(oidID);
				}
				else
				{
					if (curveName.IndexOf(' ') > 0)
					{
						curveName = curveName.Substring(curveName.IndexOf(' ') + 1);
						domainParameters = ECUtil.getNamedCurveByName(curveName);
					}
					else
					{
						domainParameters = ECUtil.getNamedCurveByName(curveName);
					}
				}
			}
			catch (IllegalArgumentException)
			{
				domainParameters = ECUtil.getNamedCurveByName(curveName);
			}
			return domainParameters;
		}

		internal static X962Parameters getDomainParametersFromName(ECParameterSpec ecSpec, bool withCompression)
		{
			X962Parameters @params;

			if (ecSpec is ECNamedCurveSpec)
			{
				ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)ecSpec).getName());
				if (curveOid == null)
				{
					curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec)ecSpec).getName());
				}
				@params = new X962Parameters(curveOid);
			}
			else if (ecSpec == null)
			{
				@params = new X962Parameters(DERNull.INSTANCE);
			}
			else
			{
				ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

				X9ECParameters ecP = new X9ECParameters(curve, EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());

				@params = new X962Parameters(ecP);
			}

			return @params;
		}
	}

}