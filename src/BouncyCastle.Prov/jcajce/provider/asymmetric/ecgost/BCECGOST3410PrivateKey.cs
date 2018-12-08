using org.bouncycastle.jce.interfaces;
using org.bouncycastle.jce.spec;
using org.bouncycastle.asn1.sec;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ecgost
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
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
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using ECGOST3410NamedCurveTable = org.bouncycastle.jce.ECGOST3410NamedCurveTable;
	using ECPointEncoder = org.bouncycastle.jce.interfaces.ECPointEncoder;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	public class BCECGOST3410PrivateKey : ECPrivateKey, ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder
	{
		internal const long serialVersionUID = 7245981689601667138L;

		private string algorithm = "ECGOST3410";
		private bool withCompression;

		[NonSerialized]
		private ASN1Encodable gostParams;
		[NonSerialized]
		private BigInteger d;
		[NonSerialized]
		private ECParameterSpec ecSpec;
		[NonSerialized]
		private DERBitString publicKey;
		[NonSerialized]
		private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public BCECGOST3410PrivateKey()
		{
		}

		public BCECGOST3410PrivateKey(ECPrivateKey key)
		{
			this.d = key.getS();
			this.algorithm = key.getAlgorithm();
			this.ecSpec = key.getParams();
		}

		public BCECGOST3410PrivateKey(ECPrivateKeySpec spec)
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


		public BCECGOST3410PrivateKey(ECPrivateKeySpec spec)
		{
			this.d = spec.getS();
			this.ecSpec = spec.getParams();
		}

		public BCECGOST3410PrivateKey(BCECGOST3410PrivateKey key)
		{
			this.d = key.d;
			this.ecSpec = key.ecSpec;
			this.withCompression = key.withCompression;
			this.attrCarrier = key.attrCarrier;
			this.publicKey = key.publicKey;
			this.gostParams = key.gostParams;
		}

		public BCECGOST3410PrivateKey(string algorithm, ECPrivateKeyParameters @params, BCECGOST3410PublicKey pubKey, ECParameterSpec spec)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();

			if (spec == null)
			{
				ECDomainParameters dp = @params.getParameters();
				EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
			}
			else
			{
				this.ecSpec = spec;
			}

			this.gostParams = pubKey.getGostParams();

			publicKey = getPublicKeyDetails(pubKey);
		}

		public BCECGOST3410PrivateKey(string algorithm, ECPrivateKeyParameters @params, BCECGOST3410PublicKey pubKey, ECParameterSpec spec)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();

			if (spec == null)
			{
				ECDomainParameters dp = @params.getParameters();
				EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
			}
			else
			{
				EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

				this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH().intValue());
			}

			this.gostParams = pubKey.getGostParams();

			publicKey = getPublicKeyDetails(pubKey);
		}

		public BCECGOST3410PrivateKey(string algorithm, ECPrivateKeyParameters @params)
		{
			this.algorithm = algorithm;
			this.d = @params.getD();
			this.ecSpec = null;
		}

		public BCECGOST3410PrivateKey(PrivateKeyInfo info)
		{
			populateFromPrivKeyInfo(info);
		}

		private void populateFromPrivKeyInfo(PrivateKeyInfo info)
		{
			AlgorithmIdentifier pkAlg = info.getPrivateKeyAlgorithm();
			ASN1Encodable pkParams = pkAlg.getParameters();
			ASN1Primitive p = pkParams.toASN1Primitive();

			if (p is ASN1Sequence && (ASN1Sequence.getInstance(p).size() == 2 || ASN1Sequence.getInstance(p).size() == 3))
			{
				GOST3410PublicKeyAlgParameters gParams = GOST3410PublicKeyAlgParameters.getInstance(pkParams);
				gostParams = gParams;

				ECNamedCurveParameterSpec spec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(gParams.getPublicKeyParamSet()));

				ECCurve curve = spec.getCurve();
				EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, spec.getSeed());

				ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(gParams.getPublicKeyParamSet()), ellipticCurve, EC5Util.convertPoint(spec.getG()), spec.getN(), spec.getH());

				ASN1Encodable privKey = info.parsePrivateKey();

				if (privKey is ASN1Integer)
				{
					this.d = ASN1Integer.getInstance(privKey).getPositiveValue();
				}
				else
				{
					byte[] encVal = ASN1OctetString.getInstance(privKey).getOctets();
					byte[] dVal = new byte[encVal.Length];

					for (int i = 0; i != encVal.Length; i++)
					{
						dVal[i] = encVal[encVal.Length - 1 - i];
					}

					this.d = new BigInteger(1, dVal);
				}
			}
			else
			{
				// for backwards compatibility
				X962Parameters @params = X962Parameters.getInstance(pkParams);

				if (@params.isNamedCurve())
				{
					ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(@params.getParameters());
					X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);

					string curveName;
					if (ecP == null) // GOST Curve
					{
						ECDomainParameters gParam = ECGOST3410NamedCurves.getByOID(oid);
						ecP = new X9ECParameters(gParam.getCurve(), gParam.getG(), gParam.getN(), gParam.getH(), gParam.getSeed());

						curveName = ECGOST3410NamedCurves.getName(oid);
					}
					else
					{
						curveName = ECUtil.getCurveName(oid);
					}

					EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

					ecSpec = new ECNamedCurveSpec(curveName, ellipticCurve, EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH());
				}
				else if (@params.isImplicitlyCA())
				{
					ecSpec = null;
				}
				else
				{
					X9ECParameters ecP = X9ECParameters.getInstance(@params.getParameters());
					EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

					this.ecSpec = new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(ecP.getG()), ecP.getN(), ecP.getH().intValue());
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
			if (gostParams != null)
			{
				byte[] encKey = new byte[32];

				extractBytes(encKey, 0, this.getS());

				try
				{
					PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3410_2001, gostParams), new DEROctetString(encKey));

					return info.getEncoded(ASN1Encoding_Fields.DER);
				}
				catch (IOException)
				{
					return null;
				}
			}
			else
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
					info = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3410_2001, @params.toASN1Primitive()), keyStructure.toASN1Primitive());

					return info.getEncoded(ASN1Encoding_Fields.DER);
				}
				catch (IOException)
				{
					return null;
				}
			}
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
			if (!(o is BCECGOST3410PrivateKey))
			{
				return false;
			}

			BCECGOST3410PrivateKey other = (BCECGOST3410PrivateKey)o;

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

		private DERBitString getPublicKeyDetails(BCECGOST3410PublicKey pub)
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