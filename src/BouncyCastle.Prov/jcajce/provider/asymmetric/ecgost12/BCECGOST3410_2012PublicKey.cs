using org.bouncycastle.jce.interfaces;
using org.bouncycastle.jce.spec;
using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.math.ec;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ecgost12
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using ECGOST3410NamedCurves = org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
	using GOST3410PublicKeyAlgParameters = org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
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
	using ECGOST3410NamedCurveTable = org.bouncycastle.jce.ECGOST3410NamedCurveTable;
	using ECPointEncoder = org.bouncycastle.jce.interfaces.ECPointEncoder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	/// <summary>
	/// Represent two kind of GOST34.10 2012 PublicKeys: with 256 and 512 size
	/// </summary>
	public class BCECGOST3410_2012PublicKey : ECPublicKey, ECPublicKey, ECPointEncoder
	{
		internal const long serialVersionUID = 7026240464295649314L;

		private string algorithm = "ECGOST3410-2012";
		private bool withCompression;

		[NonSerialized]
		private ECPublicKeyParameters ecPublicKey;
		[NonSerialized]
		private ECParameterSpec ecSpec;
		[NonSerialized]
		private GOST3410PublicKeyAlgParameters gostParams;

		public BCECGOST3410_2012PublicKey(BCECGOST3410_2012PublicKey key)
		{
			this.ecPublicKey = key.ecPublicKey;
			this.ecSpec = key.ecSpec;
			this.withCompression = key.withCompression;
			this.gostParams = key.gostParams;
		}

		public BCECGOST3410_2012PublicKey(ECPublicKeySpec spec)
		{
			this.ecSpec = spec.getParams();
			this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(ecSpec, spec.getW(), false), EC5Util.getDomainParameters(null, spec.getParams()));
		}

		public BCECGOST3410_2012PublicKey(ECPublicKeySpec spec, ProviderConfiguration configuration)
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

		public BCECGOST3410_2012PublicKey(string algorithm, ECPublicKeyParameters @params, ECParameterSpec spec)
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

		public BCECGOST3410_2012PublicKey(string algorithm, ECPublicKeyParameters @params, ECParameterSpec spec)
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
				EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

				this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec);
			}
		}

		/*
		 * called for implicitCA
		 */
		public BCECGOST3410_2012PublicKey(string algorithm, ECPublicKeyParameters @params)
		{
			this.algorithm = algorithm;
			this.ecPublicKey = @params;
			this.ecSpec = null;
		}

		private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp)
		{
			return new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
		}

		public BCECGOST3410_2012PublicKey(ECPublicKey key)
		{
			this.algorithm = key.getAlgorithm();
			this.ecSpec = key.getParams();
			this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(this.ecSpec, key.getW(), false), EC5Util.getDomainParameters(null, key.getParams()));
		}

		public BCECGOST3410_2012PublicKey(SubjectPublicKeyInfo info)
		{
			populateFromPubKeyInfo(info);
		}

		private void populateFromPubKeyInfo(SubjectPublicKeyInfo info)
		{
			ASN1ObjectIdentifier algOid = info.getAlgorithm().getAlgorithm();
			DERBitString bits = info.getPublicKeyData();
			ASN1OctetString key;
			this.algorithm = "ECGOST3410-2012";

			try
			{
				key = (ASN1OctetString)ASN1Primitive.fromByteArray(bits.getBytes());
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("error recovering public key");
			}

			byte[] keyEnc = key.getOctets();

			int fieldSize = 32;
			if (algOid.Equals(RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512))
			{
				fieldSize = 64;
			}

			int keySize = 2 * fieldSize;

			byte[] x9Encoding = new byte[1 + keySize];
			x9Encoding[0] = 0x04;
			for (int i = 1; i <= fieldSize; ++i)
			{
				x9Encoding[i] = keyEnc[fieldSize - i];
				x9Encoding[i + fieldSize] = keyEnc[keySize - i];
			}

			this.gostParams = GOST3410PublicKeyAlgParameters.getInstance(info.getAlgorithm().getParameters());

			ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(gostParams.getPublicKeyParamSet()));

			ECCurve curve = spec.getCurve();
			EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getSeed());

			this.ecPublicKey = new ECPublicKeyParameters(curve.decodePoint(x9Encoding), ECUtil.getDomainParameters(null, spec));

			this.ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(gostParams.getPublicKeyParamSet()), ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH());
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

	//        ecPublicKey.getQ().
			BigInteger bX = this.ecPublicKey.getQ().getAffineXCoord().toBigInteger();
			BigInteger bY = this.ecPublicKey.getQ().getAffineYCoord().toBigInteger();

			// need to detect key size
			bool is512 = (bX.bitLength() > 256);

			@params = getGostParams();

			if (@params == null)
			{
				if (ecSpec is ECNamedCurveSpec)
				{
					if (is512)
					{
						@params = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)ecSpec).getName()), RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512);
					}
					else
					{
						@params = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)ecSpec).getName()), RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256);
					}
				}
				else
				{ // strictly speaking this may not be applicable...
					ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

					X9ECParameters ecP = new X9ECParameters(curve, EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());

					@params = new X962Parameters(ecP);
				}
			}

			int encKeySize;
			int offset;
			ASN1ObjectIdentifier algIdentifier;
			if (is512)
			{
				encKeySize = 128;
				offset = 64;
				algIdentifier = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512;
			}
			else
			{
				encKeySize = 64;
				offset = 32;
				algIdentifier = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_256;
			}

			byte[] encKey = new byte[encKeySize];

			extractBytes(encKey, encKeySize / 2, 0, bX);
			extractBytes(encKey, encKeySize / 2, offset, bY);

			try
			{
				info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(algIdentifier, @params), new DEROctetString(encKey));
			}
			catch (IOException)
			{
				return null;
			}

			return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
		}

		private void extractBytes(byte[] encKey, int size, int offSet, BigInteger bI)
		{
			byte[] val = bI.toByteArray();
			if (val.Length < size)
			{
				byte[] tmp = new byte[size];
				JavaSystem.arraycopy(val, 0, tmp, tmp.Length - val.Length, val.Length);
				val = tmp;
			}

			for (int i = 0; i != size; i++)
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
			return EC5Util.convertPoint(ecPublicKey.getQ());
		}

		public virtual ECPoint getQ()
		{
			if (ecSpec == null)
			{
				return ecPublicKey.getQ().getDetachedPoint();
			}

			return ecPublicKey.getQ();
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
			if (!(o is BCECGOST3410_2012PublicKey))
			{
				return false;
			}

			BCECGOST3410_2012PublicKey other = (BCECGOST3410_2012PublicKey)o;

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

		public virtual GOST3410PublicKeyAlgParameters getGostParams()
		{
			if (gostParams == null && ecSpec is ECNamedCurveSpec)
			{
				BigInteger bX = this.ecPublicKey.getQ().getAffineXCoord().toBigInteger();

				// need to detect key size
				bool is512 = (bX.bitLength() > 256);
				if (is512)
				{
					this.gostParams = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)ecSpec).getName()), RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512);
				}
				else
				{
					this.gostParams = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)ecSpec).getName()), RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256);
				}
			}
			return gostParams;
		}
	}

}