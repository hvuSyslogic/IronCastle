using org.bouncycastle.jce.interfaces;
using org.bouncycastle.jce.spec;
using org.bouncycastle.asn1.ua;
using org.bouncycastle.asn1.sec;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dstu
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
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
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using ECPointEncoder = org.bouncycastle.jce.interfaces.ECPointEncoder;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	public class BCDSTU4145PrivateKey : ECPrivateKey, ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
	{
		internal const long serialVersionUID = 7245981689601667138L;

		private string algorithm = "DSTU4145";
		private bool withCompression;

		[NonSerialized]
		private BigInteger d;
		[NonSerialized]
		private ECParameterSpec ecSpec;
		[NonSerialized]
		private DERBitString publicKey;
		[NonSerialized]
		private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public BCDSTU4145PrivateKey()
		{
		}

		public BCDSTU4145PrivateKey(ECPrivateKey key)
		{
			this.d = key.getS();
			this.algorithm = key.getAlgorithm();
			this.ecSpec = key.getParams();
		}

		public BCDSTU4145PrivateKey(ECPrivateKeySpec spec)
		{
			this.d = spec.getD();

			if (spec.getParams() != null) // can be null if implicitlyCA
			{
				ECCurve curve = spec.getParams().getCurve();
				EllipticCurve ellipticCurve;

				ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

				this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
			}
			else
			{
				this.ecSpec = null;
			}
		}


		public BCDSTU4145PrivateKey(ECPrivateKeySpec spec)
		{
			this.d = spec.getS();
			this.ecSpec = spec.getParams();
		}

		public BCDSTU4145PrivateKey(BCDSTU4145PrivateKey key)
		{
			this.d = key.d;
			this.ecSpec = key.ecSpec;
			this.withCompression = key.withCompression;
			this.attrCarrier = key.attrCarrier;
			this.publicKey = key.publicKey;
		}

		public BCDSTU4145PrivateKey(string algorithm, ECPrivateKeyParameters @params, BCDSTU4145PublicKey pubKey, ECParameterSpec spec)
		{
			ECDomainParameters dp = @params.getParameters();

			this.algorithm = algorithm;
			this.d = @params.getD();

			if (spec == null)
			{
				EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
			}
			else
			{
				this.ecSpec = spec;
			}

			publicKey = getPublicKeyDetails(pubKey);
		}

		public BCDSTU4145PrivateKey(string algorithm, ECPrivateKeyParameters @params, BCDSTU4145PublicKey pubKey, ECParameterSpec spec)
		{
			ECDomainParameters dp = @params.getParameters();

			this.algorithm = algorithm;
			this.d = @params.getD();

			if (spec == null)
			{
				EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
			}
			else
			{
				EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH().intValue());
			}

			publicKey = getPublicKeyDetails(pubKey);
		}

		public BCDSTU4145PrivateKey(string algorithm, ECPrivateKeyParameters @params)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();
			this.ecSpec = null;
		}

		public BCDSTU4145PrivateKey(PrivateKeyInfo info)
		{
			populateFromPrivKeyInfo(info);
		}

		private void populateFromPrivKeyInfo(PrivateKeyInfo info)
		{
			X962Parameters @params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());

			if (@params.isNamedCurve())
			{
				ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(@params.getParameters());
				X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);

				if (ecP == null) // DSTU Curve
				{
					ECDomainParameters gParam = DSTU4145NamedCurves.getByOID(oid);
					EllipticCurve ellipticCurve = EC5Util.convertCurve(gParam.getCurve(), gParam.getSeed());

					ecSpec = new ECNamedCurveSpec(oid.getId(), ellipticCurve, EC5Util.convertPoint(gParam.getG()), gParam.getN(), gParam.getH());
				}
				else
				{
					EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

					ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(oid), ellipticCurve, EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH());
				}
			}
			else if (@params.isImplicitlyCA())
			{
				ecSpec = null;
			}
			else
			{
				ASN1Sequence seq = ASN1Sequence.getInstance(@params.getParameters());

				if (seq.getObjectAt(0) is ASN1Integer)
				{
					X9ECParameters ecP = X9ECParameters.getInstance(@params.getParameters());
					EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

					this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH().intValue());
				}
				else
				{
					DSTU4145Params dstuParams = DSTU4145Params.getInstance(seq);
					ECParameterSpec spec;
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
						if (info.getPrivateKeyAlgorithm().getAlgorithm().Equals(UAObjectIdentifiers_Fields.dstu4145le))
						{
							reverseBytes(b_bytes);
						}
						DSTU4145BinaryField field = binary.getField();
						ECCurve curve = new ECCurve.F2m(field.getM(), field.getK1(), field.getK2(), field.getK3(), binary.getA(), new BigInteger(1, b_bytes));
						byte[] g_bytes = binary.getG();
						if (info.getPrivateKeyAlgorithm().getAlgorithm().Equals(UAObjectIdentifiers_Fields.dstu4145le))
						{
							reverseBytes(g_bytes);
						}
						spec = new ECParameterSpec(curve, DSTU4145PointEncoder.decodePoint(curve, g_bytes), binary.getN());
					}

					EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

					this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH().intValue());
				}
			}

			ASN1Encodable privKey = info.parsePrivateKey();
			if (privKey is ASN1Integer)
			{
				ASN1Integer derD = ASN1Integer.getInstance(privKey);

				this.d = derD.getValue();
			}
			else
			{
				ECPrivateKey ec = ECPrivateKey.getInstance(privKey);

				this.d = ec.getKey();
				this.publicKey = ec.getPublicKey();
			}
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

		public virtual string getAlgorithm()
		{
			return algorithm;
		}

		/// <summary>
		/// return the encoding format we produce in getEncoded().
		/// </summary>
		/// <returns> the string "PKCS#8" </returns>
		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		/// <summary>
		/// Return a PKCS8 representation of the key. The sequence returned
		/// represents a full PrivateKeyInfo object.
		/// </summary>
		/// <returns> a PKCS8 representation of the key. </returns>
		public virtual byte[] getEncoded()
		{
			X962Parameters @params;
			int orderBitLength;

			if (ecSpec is ECNamedCurveSpec)
			{
				ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)ecSpec).getName());
				if (curveOid == null) // guess it's the OID
				{
					curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec)ecSpec).getName());
				}
				@params = new X962Parameters(curveOid);
				orderBitLength = ECUtil.getOrderBitLength(BouncyCastleProvider.CONFIGURATION, ecSpec.getOrder(), this.getS());
			}
			else if (ecSpec == null)
			{
				@params = new X962Parameters(DERNull.INSTANCE);
				orderBitLength = ECUtil.getOrderBitLength(BouncyCastleProvider.CONFIGURATION, null, this.getS());
			}
			else
			{
				ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

				X9ECParameters ecP = new X9ECParameters(curve, EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression), ecSpec.getOrder(), BigInteger.valueOf(ecSpec.getCofactor()), ecSpec.getCurve().getSeed());

				@params = new X962Parameters(ecP);
				orderBitLength = ECUtil.getOrderBitLength(BouncyCastleProvider.CONFIGURATION, ecSpec.getOrder(), this.getS());
			}

			PrivateKeyInfo info;
			ECPrivateKey keyStructure;

			if (publicKey != null)
			{
				keyStructure = new ECPrivateKey(orderBitLength, this.getS(), publicKey, @params);
			}
			else
			{
				keyStructure = new ECPrivateKey(orderBitLength, this.getS(), @params);
			}

			try
			{
				if (algorithm.Equals("DSTU4145"))
				{
					info = new PrivateKeyInfo(new AlgorithmIdentifier(UAObjectIdentifiers_Fields.dstu4145be, @params.toASN1Primitive()), keyStructure.toASN1Primitive());
				}
				else
				{

					info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params.toASN1Primitive()), keyStructure.toASN1Primitive());
				}

				return info.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual ECParameterSpec getParams()
		{
			return ecSpec;
		}

		public virtual ECParameterSpec getParameters()
		{
			if (ecSpec == null)
			{
				return null;
			}

			return EC5Util.convertSpec(ecSpec, withCompression);
		}

		public virtual ECParameterSpec engineGetSpec()
		{
			if (ecSpec != null)
			{
				return EC5Util.convertSpec(ecSpec, withCompression);
			}

			return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
		}

		public virtual BigInteger getS()
		{
			return d;
		}

		public virtual BigInteger getD()
		{
			return d;
		}

		public virtual void setBagAttribute(ASN1ObjectIdentifier oid, ASN1Encodable attribute)
		{
			attrCarrier.setBagAttribute(oid, attribute);
		}

		public virtual ASN1Encodable getBagAttribute(ASN1ObjectIdentifier oid)
		{
			return attrCarrier.getBagAttribute(oid);
		}

		public virtual Enumeration getBagAttributeKeys()
		{
			return attrCarrier.getBagAttributeKeys();
		}

		public virtual void setPointFormat(string style)
		{
			withCompression = !("UNCOMPRESSED".Equals(style, StringComparison.OrdinalIgnoreCase));
		}

		public override bool Equals(object o)
		{
			if (!(o is BCDSTU4145PrivateKey))
			{
				return false;
			}

			BCDSTU4145PrivateKey other = (BCDSTU4145PrivateKey)o;

			return getD().Equals(other.getD()) && (engineGetSpec().Equals(other.engineGetSpec()));
		}

		public override int GetHashCode()
		{
			return getD().GetHashCode() ^ engineGetSpec().GetHashCode();
		}

		public override string ToString()
		{
			return ECUtil.privateKeyToString(algorithm, d, engineGetSpec());
		}

		private DERBitString getPublicKeyDetails(BCDSTU4145PublicKey pub)
		{
			try
			{
				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

				return info.getPublicKeyData();
			}
			catch (IOException)
			{ // should never happen
				return null;
			}
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			byte[] enc = (byte[])@in.readObject();

			populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

			this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}