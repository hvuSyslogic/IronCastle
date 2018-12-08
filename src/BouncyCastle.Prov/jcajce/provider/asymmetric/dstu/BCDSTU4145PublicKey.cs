using org.bouncycastle.jce.interfaces;
using org.bouncycastle.jce.spec;
using org.bouncycastle.asn1.ua;
using org.bouncycastle.math.ec;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dstu
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DSTU4145BinaryField = org.bouncycastle.asn1.ua.DSTU4145BinaryField;
	using DSTU4145ECBinary = org.bouncycastle.asn1.ua.DSTU4145ECBinary;
	using DSTU4145NamedCurves = org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
	using DSTU4145Params = org.bouncycastle.asn1.ua.DSTU4145Params;
	using DSTU4145PointEncoder = org.bouncycastle.asn1.ua.DSTU4145PointEncoder;
	using UAObjectIdentifiers = org.bouncycastle.asn1.ua.UAObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using ECPointEncoder = org.bouncycastle.jce.interfaces.ECPointEncoder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	public class BCDSTU4145PublicKey : ECPublicKey, ECPublicKey, ECPointEncoder
	{
		internal const long serialVersionUID = 7026240464295649314L;

		private string algorithm = "DSTU4145";
		private bool withCompression;

		[NonSerialized]
		private ECPublicKeyParameters ecPublicKey;
		[NonSerialized]
		private ECParameterSpec ecSpec;
		[NonSerialized]
		private DSTU4145Params dstuParams;

		public BCDSTU4145PublicKey(BCDSTU4145PublicKey key)
		{
			this.ecPublicKey = key.ecPublicKey;
			this.ecSpec = key.ecSpec;
			this.withCompression = key.withCompression;
			this.dstuParams = key.dstuParams;
		}

		public BCDSTU4145PublicKey(ECPublicKeySpec spec)
		{
			this.ecSpec = spec.getParams();
			this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(ecSpec, spec.getW(), false), EC5Util.getDomainParameters(null, ecSpec));
		}

		public BCDSTU4145PublicKey(ECPublicKeySpec spec, ProviderConfiguration configuration)
		{
			if (spec.getParams() != null) // can be null if implictlyCa
			{
				ECCurve curve = spec.getParams().getCurve();
				EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

				// this may seem a little long-winded but it's how we pick up the custom curve.
				this.ecPublicKey = new ECPublicKeyParameters(spec.getQ(), ECUtil.getDomainParameters(configuration, spec.getParams()));
				this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
			}
			else
			{
				ECParameterSpec s = configuration.getEcImplicitlyCa();

				this.ecPublicKey = new ECPublicKeyParameters(s.getCurve().createPoint(spec.getQ().getAffineXCoord().toBigInteger(), spec.getQ().getAffineYCoord().toBigInteger()), EC5Util.getDomainParameters(configuration, (ECParameterSpec)null));
				this.ecSpec = null;
			}
		}

		public BCDSTU4145PublicKey(string algorithm, ECPublicKeyParameters @params, ECParameterSpec spec)
		{
			ECDomainParameters dp = @params.getParameters();

			this.algorithm = algorithm;
			this.ecPublicKey = @params;

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

		public BCDSTU4145PublicKey(string algorithm, ECPublicKeyParameters @params, ECParameterSpec spec)
		{
			ECDomainParameters dp = @params.getParameters();

			this.algorithm = algorithm;

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

			this.ecPublicKey = @params;
		}

		/*
		 * called for implicitCA
		 */
		public BCDSTU4145PublicKey(string algorithm, ECPublicKeyParameters @params)
		{
			this.algorithm = algorithm;
			this.ecPublicKey = @params;
			this.ecSpec = null;
		}

		private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp)
		{
			return new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
		}

		public BCDSTU4145PublicKey(SubjectPublicKeyInfo info)
		{
			populateFromPubKeyInfo(info);
		}

		private void reverseBytes(byte[] bytes)
		{
			byte tmp;

			for (int i = 0; i < bytes.Length / 2; i++)
			{
				tmp = bytes[i];
				bytes[i] = bytes[bytes.Length - 1 - i];
				bytes[bytes.Length - 1 - i] = tmp;
			}
		}

		private void populateFromPubKeyInfo(SubjectPublicKeyInfo info)
		{
			DERBitString bits = info.getPublicKeyData();
			ASN1OctetString key;
			this.algorithm = "DSTU4145";

			try
			{
				key = (ASN1OctetString)ASN1Primitive.fromByteArray(bits.getBytes());
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("error recovering public key");
			}

			byte[] keyEnc = key.getOctets();

			if (info.getAlgorithm().getAlgorithm().Equals(UAObjectIdentifiers_Fields.dstu4145le))
			{
				reverseBytes(keyEnc);
			}

			ASN1Sequence seq = ASN1Sequence.getInstance(info.getAlgorithm().getParameters());
			ECParameterSpec spec = null;
			X9ECParameters x9Params = null;

			if (seq.getObjectAt(0) is ASN1Integer)
			{
				x9Params = X9ECParameters.getInstance(seq);
				spec = new ECParameterSpec(x9Params.getCurve(), x9Params.getG(), x9Params.getN(), x9Params.getH(), x9Params.getSeed());
			}
			else
			{
				dstuParams = DSTU4145Params.getInstance(seq);

				if (dstuParams.isNamedCurve())
				{
					ASN1ObjectIdentifier curveOid = dstuParams.getNamedCurve();
					ECDomainParameters ecP = DSTU4145NamedCurves.getByOID(curveOid);

					spec = new ECNamedCurveParameterSpec(curveOid.getId(), ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
				}
				else
				{
					DSTU4145ECBinary binary = dstuParams.getECBinary();
					byte[] b_bytes = binary.getB();
					if (info.getAlgorithm().getAlgorithm().Equals(UAObjectIdentifiers_Fields.dstu4145le))
					{
						reverseBytes(b_bytes);
					}
					DSTU4145BinaryField field = binary.getField();
					ECCurve curve = new ECCurve.F2m(field.getM(), field.getK1(), field.getK2(), field.getK3(), binary.getA(), new BigInteger(1, b_bytes));
					byte[] g_bytes = binary.getG();
					if (info.getAlgorithm().getAlgorithm().Equals(UAObjectIdentifiers_Fields.dstu4145le))
					{
						reverseBytes(g_bytes);
					}
					spec = new ECParameterSpec(curve, DSTU4145PointEncoder.decodePoint(curve, g_bytes), binary.getN());
				}
			}

			ECCurve curve = spec.getCurve();
			EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getSeed());

			if (dstuParams != null)
			{
				if (dstuParams.isNamedCurve())
				{
					ecSpec = new ECNamedCurveSpec(dstuParams.getNamedCurve().getId(), ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH());
				}
				else
				{
					ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH().intValue());
				}
			}
			else
			{
				ecSpec = EC5Util.convertToSpec(x9Params);
			}

			//this.q = curve.createPoint(new BigInteger(1, x), new BigInteger(1, y), false);
			this.ecPublicKey = new ECPublicKeyParameters(DSTU4145PointEncoder.decodePoint(curve, keyEnc), EC5Util.getDomainParameters(null, ecSpec));
		}

		public virtual byte[] getSbox()
		{
			if (null != dstuParams)
			{
				return dstuParams.getDKE();
			}
			else
			{
				return DSTU4145Params.getDefaultDKE();
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

			if (dstuParams != null)
			{
				@params = dstuParams;
			}
			else
			{
				if (ecSpec is ECNamedCurveSpec)
				{
					@params = new DSTU4145Params(new ASN1ObjectIdentifier(((ECNamedCurveSpec)ecSpec).getName()));
				}
				else
				{ // strictly speaking this may not be applicable...
					ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

					X9ECParameters ecP = new X9ECParameters(curve, EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());

					@params = new X962Parameters(ecP);
				}
			}

			byte[] encKey = DSTU4145PointEncoder.encodePoint(ecPublicKey.getQ());

			try
			{
				info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(UAObjectIdentifiers_Fields.dstu4145be, @params), new DEROctetString(encKey));
			}
			catch (IOException)
			{
				return null;
			}

			return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
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
			return EC5Util.convertPoint(ecPublicKey.getQ());
		}

		public virtual ECPoint getQ()
		{
			ECPoint q = ecPublicKey.getQ();

			if (ecSpec == null)
			{
				return q.getDetachedPoint();
			}

			return q;
		}

		public virtual ECPublicKeyParameters engineGetKeyParameters()
		{
			return ecPublicKey;
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
			return ECUtil.publicKeyToString(algorithm, ecPublicKey.getQ(), engineGetSpec());
		}

		public virtual void setPointFormat(string style)
		{
			withCompression = !("UNCOMPRESSED".Equals(style, StringComparison.OrdinalIgnoreCase));
		}

		public override bool Equals(object o)
		{
			if (!(o is BCDSTU4145PublicKey))
			{
				return false;
			}

			BCDSTU4145PublicKey other = (BCDSTU4145PublicKey)o;

			return ecPublicKey.getQ().Equals(other.ecPublicKey.getQ()) && (engineGetSpec().Equals(other.engineGetSpec()));
		}

		public override int GetHashCode()
		{
			return ecPublicKey.getQ().GetHashCode() ^ engineGetSpec().GetHashCode();
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			byte[] enc = (byte[])@in.readObject();

			populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}