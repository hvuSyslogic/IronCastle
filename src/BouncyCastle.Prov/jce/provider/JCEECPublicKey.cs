using org.bouncycastle.jce.interfaces;
using org.bouncycastle.math.ec;
using org.bouncycastle.jce.spec;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.x9;

using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using ECGOST3410NamedCurves = org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
	using GOST3410PublicKeyAlgParameters = org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ECPoint = org.bouncycastle.asn1.x9.X9ECPoint;
	using X9IntegerConverter = org.bouncycastle.asn1.x9.X9IntegerConverter;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using ECPointEncoder = org.bouncycastle.jce.interfaces.ECPointEncoder;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using SecP256K1Point = org.bouncycastle.math.ec.custom.sec.SecP256K1Point;
	using SecP256R1Point = org.bouncycastle.math.ec.custom.sec.SecP256R1Point;
	using Strings = org.bouncycastle.util.Strings;

	public class JCEECPublicKey : ECPublicKey, ECPublicKey, ECPointEncoder
	{
		private string algorithm = "EC";
		private ECPoint q;
		private ECParameterSpec ecSpec;
		private bool withCompression;
		private GOST3410PublicKeyAlgParameters gostParams;

		public JCEECPublicKey(string algorithm, JCEECPublicKey key)
		{
			this.algorithm = algorithm;
			this.q = key.q;
			this.ecSpec = key.ecSpec;
			this.withCompression = key.withCompression;
			this.gostParams = key.gostParams;
		}

		public JCEECPublicKey(string algorithm, ECPublicKeySpec spec)
		{
			this.algorithm = algorithm;
			this.ecSpec = spec.getParams();
			this.q = EC5Util.convertPoint(ecSpec, spec.getW(), false);
		}

		public JCEECPublicKey(string algorithm, ECPublicKeySpec spec)
		{
			this.algorithm = algorithm;
			this.q = spec.getQ();

			if (spec.getParams() != null) // can be null if implictlyCa
			{
				ECCurve curve = spec.getParams().getCurve();
				EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

				this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
			}
			else
			{
				if (q.getCurve() == null)
				{
					ECParameterSpec s = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

					q = s.getCurve().createPoint(q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger(), false);
				}
				this.ecSpec = null;
			}
		}

		public JCEECPublicKey(string algorithm, ECPublicKeyParameters @params, ECParameterSpec spec)
		{
			ECDomainParameters dp = @params.getParameters();

			this.algorithm = algorithm;
			this.q = @params.getQ();

			if (spec == null)
			{
				EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

				this.ecSpec = createSpec(ellipticCurve, dp);
			}
			else
			{
				this.ecSpec = spec;
			}
		}

		public JCEECPublicKey(string algorithm, ECPublicKeyParameters @params, ECParameterSpec spec)
		{
			ECDomainParameters dp = @params.getParameters();

			this.algorithm = algorithm;
			this.q = @params.getQ();

			if (spec == null)
			{
				EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

				this.ecSpec = createSpec(ellipticCurve, dp);
			}
			else
			{
				EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

				this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec);
			}
		}

		/*
		 * called for implicitCA
		 */
		public JCEECPublicKey(string algorithm, ECPublicKeyParameters @params)
		{
			this.algorithm = algorithm;
			this.q = @params.getQ();
			this.ecSpec = null;
		}

		private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp)
		{
			return new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
		}

		public JCEECPublicKey(ECPublicKey key)
		{
			this.algorithm = key.getAlgorithm();
			this.ecSpec = key.getParams();
			this.q = EC5Util.convertPoint(this.ecSpec, key.getW(), false);
		}

		public JCEECPublicKey(SubjectPublicKeyInfo info)
		{
			populateFromPubKeyInfo(info);
		}

		private void populateFromPubKeyInfo(SubjectPublicKeyInfo info)
		{
			if (info.getAlgorithmId().getAlgorithm().Equals(CryptoProObjectIdentifiers_Fields.gostR3410_2001))
			{
				DERBitString bits = info.getPublicKeyData();
				ASN1OctetString key;
				this.algorithm = "ECGOST3410";

				try
				{
					key = (ASN1OctetString) ASN1Primitive.fromByteArray(bits.getBytes());
				}
				catch (IOException)
				{
					throw new IllegalArgumentException("error recovering public key");
				}

				byte[] keyEnc = key.getOctets();

				byte[] x9Encoding = new byte[65];
				x9Encoding[0] = 0x04;
				for (int i = 1; i <= 32; ++i)
				{
					x9Encoding[i] = keyEnc[32 - i];
					x9Encoding[i + 32] = keyEnc[64 - i];
				}

				gostParams = new GOST3410PublicKeyAlgParameters((ASN1Sequence)info.getAlgorithmId().getParameters());

				ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(gostParams.getPublicKeyParamSet()));

				ECCurve curve = spec.getCurve();
				EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getSeed());

				this.q = curve.decodePoint(x9Encoding);

				ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(gostParams.getPublicKeyParamSet()), ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH());
			}
			else
			{
				X962Parameters @params = new X962Parameters((ASN1Primitive)info.getAlgorithmId().getParameters());
				ECCurve curve;
				EllipticCurve ellipticCurve;

				if (@params.isNamedCurve())
				{
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)@params.getParameters();
					X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);

					curve = ecP.getCurve();
					ellipticCurve = EC5Util.convertCurve(curve, ecP.getSeed());

					ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(oid), ellipticCurve, EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH());
				}
				else if (@params.isImplicitlyCA())
				{
					ecSpec = null;
					curve = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getCurve();
				}
				else
				{
					X9ECParameters ecP = X9ECParameters.getInstance(@params.getParameters());

					curve = ecP.getCurve();
					ellipticCurve = EC5Util.convertCurve(curve, ecP.getSeed());

					this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH().intValue());
				}

				DERBitString bits = info.getPublicKeyData();
				byte[] data = bits.getBytes();
				ASN1OctetString key = new DEROctetString(data);

				//
				// extra octet string - one of our old certs...
				//
				if (data[0] == 0x04 && data[1] == data.Length - 2 && (data[2] == 0x02 || data[2] == 0x03))
				{
					int qLength = (new X9IntegerConverter()).getByteLength(curve);

					if (qLength >= data.Length - 3)
					{
						try
						{
							key = (ASN1OctetString) ASN1Primitive.fromByteArray(data);
						}
						catch (IOException)
						{
							throw new IllegalArgumentException("error recovering public key");
						}
					}
				}
				X9ECPoint derQ = new X9ECPoint(curve, key);

				this.q = derQ.getPoint();
			}
		}

		public virtual string getAlgorithm()
		{
			return algorithm;
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getEncoded()
		{
			ASN1Encodable @params;
			SubjectPublicKeyInfo info;

			if (algorithm.Equals("ECGOST3410"))
			{
				if (gostParams != null)
				{
					@params = gostParams;
				}
				else
				{
					if (ecSpec is ECNamedCurveSpec)
					{
						@params = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)ecSpec).getName()), CryptoProObjectIdentifiers_Fields.gostR3411_94_CryptoProParamSet);
					}
					else
					{ // strictly speaking this may not be applicable...
						ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

						X9ECParameters ecP = new X9ECParameters(curve, EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());

						@params = new X962Parameters(ecP);
					}
				}

				BigInteger bX = this.q.getAffineXCoord().toBigInteger();
				BigInteger bY = this.q.getAffineYCoord().toBigInteger();
				byte[] encKey = new byte[64];

				extractBytes(encKey, 0, bX);
				extractBytes(encKey, 32, bY);

				try
				{
					info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3410_2001, @params), new DEROctetString(encKey));
				}
				catch (IOException)
				{
					return null;
				}
			}
			else
			{
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

				ECCurve curve = this.engineGetQ().getCurve();
				ASN1OctetString p = (ASN1OctetString) (new X9ECPoint(curve.createPoint(this.getQ().getAffineXCoord().toBigInteger(), this.getQ().getAffineYCoord().toBigInteger(), withCompression))).toASN1Primitive();

				info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), p.getOctets());
			}

			return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
		}

		private void extractBytes(byte[] encKey, int offSet, BigInteger bI)
		{
			byte[] val = bI.toByteArray();
			if (val.Length < 32)
			{
				byte[] tmp = new byte[32];
				JavaSystem.arraycopy(val, 0, tmp, tmp.Length - val.Length, val.Length);
				val = tmp;
			}

			for (int i = 0; i != 32; i++)
			{
				encKey[offSet + i] = val[val.Length - 1 - i];
			}
		}

		public virtual ECParameterSpec getParams()
		{
			return ecSpec;
		}

		public virtual ECParameterSpec getParameters()
		{
			if (ecSpec == null) // implictlyCA
			{
				return null;
			}

			return EC5Util.convertSpec(ecSpec, withCompression);
		}

		public virtual ECPoint getW()
		{
			return EC5Util.convertPoint(q);
		}

		public virtual ECPoint getQ()
		{
			if (ecSpec == null)
			{
				return q.getDetachedPoint();
			}

			return q;
		}

		public virtual ECPoint engineGetQ()
		{
			return q;
		}

		public virtual ECParameterSpec engineGetSpec()
		{
			if (ecSpec != null)
			{
				return EC5Util.convertSpec(ecSpec, withCompression);
			}

			return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append("EC Public Key").append(nl);
			buf.append("            X: ").append(this.q.getAffineXCoord().toBigInteger().ToString(16)).append(nl);
			buf.append("            Y: ").append(this.q.getAffineYCoord().toBigInteger().ToString(16)).append(nl);

			return buf.ToString();

		}

		public virtual void setPointFormat(string style)
		{
		   withCompression = !("UNCOMPRESSED".Equals(style, StringComparison.OrdinalIgnoreCase));
		}

		public override bool Equals(object o)
		{
			if (!(o is JCEECPublicKey))
			{
				return false;
			}

			JCEECPublicKey other = (JCEECPublicKey)o;

			return engineGetQ().Equals(other.engineGetQ()) && (engineGetSpec().Equals(other.engineGetSpec()));
		}

		public override int GetHashCode()
		{
			return engineGetQ().GetHashCode() ^ engineGetSpec().GetHashCode();
		}

		private void readObject(ObjectInputStream @in)
		{
			byte[] enc = (byte[])@in.readObject();

			populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

			this.algorithm = (string)@in.readObject();
			this.withCompression = @in.readBoolean();
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.writeObject(this.getEncoded());
			@out.writeObject(algorithm);
			@out.writeBoolean(withCompression);
		}
	}

}