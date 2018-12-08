using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECNamedDomainParameters = org.bouncycastle.crypto.@params.ECNamedDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using ECPrivateKey = org.bouncycastle.jce.interfaces.ECPrivateKey;
	using ECPublicKey = org.bouncycastle.jce.interfaces.ECPublicKey;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using Arrays = org.bouncycastle.util.Arrays;
	using Fingerprint = org.bouncycastle.util.Fingerprint;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// utility class for converting jce/jca ECDSA, ECDH, and ECDHC
	/// objects into their org.bouncycastle.crypto counterparts.
	/// </summary>
	public class ECUtil
	{
		/// <summary>
		/// Returns a sorted array of middle terms of the reduction polynomial. </summary>
		/// <param name="k"> The unsorted array of middle terms of the reduction polynomial
		/// of length 1 or 3. </param>
		/// <returns> the sorted array of middle terms of the reduction polynomial.
		/// This array always has length 3. </returns>
		internal static int[] convertMidTerms(int[] k)
		{
			int[] res = new int[3];

			if (k.Length == 1)
			{
				res[0] = k[0];
			}
			else
			{
				if (k.Length != 3)
				{
					throw new IllegalArgumentException("Only Trinomials and pentanomials supported");
				}

				if (k[0] < k[1] && k[0] < k[2])
				{
					res[0] = k[0];
					if (k[1] < k[2])
					{
						res[1] = k[1];
						res[2] = k[2];
					}
					else
					{
						res[1] = k[2];
						res[2] = k[1];
					}
				}
				else if (k[1] < k[2])
				{
					res[0] = k[1];
					if (k[0] < k[2])
					{
						res[1] = k[0];
						res[2] = k[2];
					}
					else
					{
						res[1] = k[2];
						res[2] = k[0];
					}
				}
				else
				{
					res[0] = k[2];
					if (k[0] < k[1])
					{
						res[1] = k[0];
						res[2] = k[1];
					}
					else
					{
						res[1] = k[1];
						res[2] = k[0];
					}
				}
			}

			return res;
		}

		public static ECDomainParameters getDomainParameters(ProviderConfiguration configuration, ECParameterSpec @params)
		{
			ECDomainParameters domainParameters;

			if (@params is ECNamedCurveParameterSpec)
			{
				ECNamedCurveParameterSpec nParams = (ECNamedCurveParameterSpec)@params;
				ASN1ObjectIdentifier nameOid = ECUtil.getNamedCurveOid(nParams.getName());

				domainParameters = new ECNamedDomainParameters(nameOid, nParams.getCurve(), nParams.getG(), nParams.getN(), nParams.getH(), nParams.getSeed());
			}
			else if (@params == null)
			{
				ECParameterSpec iSpec = configuration.getEcImplicitlyCa();

				domainParameters = new ECDomainParameters(iSpec.getCurve(), iSpec.getG(), iSpec.getN(), iSpec.getH(), iSpec.getSeed());
			}
			else
			{
				domainParameters = new ECDomainParameters(@params.getCurve(), @params.getG(), @params.getN(), @params.getH(), @params.getSeed());
			}

			return domainParameters;
		}

		public static ECDomainParameters getDomainParameters(ProviderConfiguration configuration, X962Parameters @params)
		{
			ECDomainParameters domainParameters;

			if (@params.isNamedCurve())
			{
				ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(@params.getParameters());
				X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);
				if (ecP == null)
				{
					Map extraCurves = configuration.getAdditionalECParameters();

					ecP = (X9ECParameters)extraCurves.get(oid);
				}
				domainParameters = new ECNamedDomainParameters(oid, ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
			}
			else if (@params.isImplicitlyCA())
			{
				ECParameterSpec iSpec = configuration.getEcImplicitlyCa();

				domainParameters = new ECDomainParameters(iSpec.getCurve(), iSpec.getG(), iSpec.getN(), iSpec.getH(), iSpec.getSeed());
			}
			else
			{
				X9ECParameters ecP = X9ECParameters.getInstance(@params.getParameters());

				domainParameters = new ECDomainParameters(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
			}

			return domainParameters;
		}

		public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			if (key is ECPublicKey)
			{
				ECPublicKey k = (ECPublicKey)key;
				ECParameterSpec s = k.getParameters();

				return new ECPublicKeyParameters(k.getQ(), new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
			}
			else if (key is java.security.interfaces.ECPublicKey)
			{
				java.security.interfaces.ECPublicKey pubKey = (java.security.interfaces.ECPublicKey)key;
				ECParameterSpec s = EC5Util.convertSpec(pubKey.getParams(), false);
				return new ECPublicKeyParameters(EC5Util.convertPoint(pubKey.getParams(), pubKey.getW(), false), new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
			}
			else
			{
				// see if we can build a key from key.getEncoded()
				try
				{
					byte[] bytes = key.getEncoded();

					if (bytes == null)
					{
						throw new InvalidKeyException("no encoding for EC public key");
					}

					PublicKey publicKey = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(bytes));

					if (publicKey is java.security.interfaces.ECPublicKey)
					{
						return ECUtil.generatePublicKeyParameter(publicKey);
					}
				}
				catch (Exception e)
				{
					throw new InvalidKeyException("cannot identify EC public key: " + e.ToString());
				}
			}

			throw new InvalidKeyException("cannot identify EC public key.");
		}

		public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey key)
		{
			if (key is ECPrivateKey)
			{
				ECPrivateKey k = (ECPrivateKey)key;
				ECParameterSpec s = k.getParameters();

				if (s == null)
				{
					s = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
				}

				if (k.getParameters() is ECNamedCurveParameterSpec)
				{
					string name = ((ECNamedCurveParameterSpec)k.getParameters()).getName();
					return new ECPrivateKeyParameters(k.getD(), new ECNamedDomainParameters(ECNamedCurveTable.getOID(name), s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
				}
				else
				{
					return new ECPrivateKeyParameters(k.getD(), new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
				}
			}
			else if (key is java.security.interfaces.ECPrivateKey)
			{
				java.security.interfaces.ECPrivateKey privKey = (java.security.interfaces.ECPrivateKey)key;
				ECParameterSpec s = EC5Util.convertSpec(privKey.getParams(), false);
				return new ECPrivateKeyParameters(privKey.getS(), new ECDomainParameters(s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
			}
			else
			{
				// see if we can build a key from key.getEncoded()
				try
				{
					byte[] bytes = key.getEncoded();

					if (bytes == null)
					{
						throw new InvalidKeyException("no encoding for EC private key");
					}

					PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(bytes));

					if (privateKey is java.security.interfaces.ECPrivateKey)
					{
						return ECUtil.generatePrivateKeyParameter(privateKey);
					}
				}
				catch (Exception e)
				{
					throw new InvalidKeyException("cannot identify EC private key: " + e.ToString());
				}
			}

			throw new InvalidKeyException("can't identify EC private key.");
		}

		public static int getOrderBitLength(ProviderConfiguration configuration, BigInteger order, BigInteger privateValue)
		{
			if (order == null) // implicitly CA
			{
				ECParameterSpec implicitCA = configuration.getEcImplicitlyCa();

				if (implicitCA == null)
				{
					return privateValue.bitLength(); // a guess but better than an exception!
				}

				return implicitCA.getN().bitLength();
			}
			else
			{
				return order.bitLength();
			}
		}

		public static ASN1ObjectIdentifier getNamedCurveOid(string curveName)
		{
			string name = curveName;

			int spacePos = name.IndexOf(' ');
			if (spacePos > 0)
			{
				name = name.Substring(spacePos + 1);
			}

			try
			{
				if (name[0] >= '0' && name[0] <= '2')
				{
					return new ASN1ObjectIdentifier(name);
				}
			}
			catch (IllegalArgumentException)
			{
			}

			return ECNamedCurveTable.getOID(name);
		}

		public static ASN1ObjectIdentifier getNamedCurveOid(ECParameterSpec ecParameterSpec)
		{
			for (Enumeration names = ECNamedCurveTable.getNames(); names.hasMoreElements();)
			{
				string name = (string)names.nextElement();

				X9ECParameters @params = ECNamedCurveTable.getByName(name);

				if (@params.getN().Equals(ecParameterSpec.getN()) && @params.getH().Equals(ecParameterSpec.getH()) && @params.getCurve().Equals(ecParameterSpec.getCurve()) && @params.getG().Equals(ecParameterSpec.getG()))
				{
					return ECNamedCurveTable.getOID(name);
				}
			}

			return null;
		}

		public static X9ECParameters getNamedCurveByOid(ASN1ObjectIdentifier oid)
		{
			X9ECParameters @params = CustomNamedCurves.getByOID(oid);

			if (@params == null)
			{
				@params = ECNamedCurveTable.getByOID(oid);
			}

			return @params;
		}

		public static X9ECParameters getNamedCurveByName(string curveName)
		{
			X9ECParameters @params = CustomNamedCurves.getByName(curveName);

			if (@params == null)
			{
				@params = ECNamedCurveTable.getByName(curveName);
			}

			return @params;
		}

		public static string getCurveName(ASN1ObjectIdentifier oid)
		{
			return ECNamedCurveTable.getName(oid);
		}

		public static string privateKeyToString(string algorithm, BigInteger d, ECParameterSpec spec)
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			ECPoint q = calculateQ(d, spec);

			buf.append(algorithm);
			buf.append(" Private Key [").append(ECUtil.generateKeyFingerprint(q, spec)).append("]").append(nl);
			buf.append("            X: ").append(q.getAffineXCoord().toBigInteger().ToString(16)).append(nl);
			buf.append("            Y: ").append(q.getAffineYCoord().toBigInteger().ToString(16)).append(nl);

			return buf.ToString();
		}

		private static ECPoint calculateQ(BigInteger d, ECParameterSpec spec)
		{
			return spec.getG().multiply(d).normalize();
		}

		public static string publicKeyToString(string algorithm, ECPoint q, ECParameterSpec spec)
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append(algorithm);
			buf.append(" Public Key [").append(ECUtil.generateKeyFingerprint(q, spec)).append("]").append(nl);
			buf.append("            X: ").append(q.getAffineXCoord().toBigInteger().ToString(16)).append(nl);
			buf.append("            Y: ").append(q.getAffineYCoord().toBigInteger().ToString(16)).append(nl);

			return buf.ToString();
		}

		public static string generateKeyFingerprint(ECPoint publicPoint, ECParameterSpec spec)
		{
			ECCurve curve = spec.getCurve();
			ECPoint g = spec.getG();

			if (curve != null)
			{
				return (new Fingerprint(Arrays.concatenate(publicPoint.getEncoded(false), curve.getA().getEncoded(), curve.getB().getEncoded(), g.getEncoded(false)))).ToString();
			}

			return (new Fingerprint(publicPoint.getEncoded(false))).ToString();
		}
	}

}