using org.bouncycastle.jce.interfaces;
using org.bouncycastle.jce.spec;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.math.ec;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ec
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECPoint = org.bouncycastle.asn1.x9.X9ECPoint;
	using X9IntegerConverter = org.bouncycastle.asn1.x9.X9IntegerConverter;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using ECPointEncoder = org.bouncycastle.jce.interfaces.ECPointEncoder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;

	public class BCECPublicKey : ECPublicKey, ECPublicKey, ECPointEncoder
	{
		internal const long serialVersionUID = 2422789860422731812L;

		private string algorithm = "EC";
		private bool withCompression;

		[NonSerialized]
		private ECPublicKeyParameters ecPublicKey;
		[NonSerialized]
		private ECParameterSpec ecSpec;
		[NonSerialized]
		private ProviderConfiguration configuration;

		public BCECPublicKey(string algorithm, BCECPublicKey key)
		{
			this.algorithm = algorithm;
			this.ecPublicKey = key.ecPublicKey;
			this.ecSpec = key.ecSpec;
			this.withCompression = key.withCompression;
			this.configuration = key.configuration;
		}

		public BCECPublicKey(string algorithm, ECPublicKeySpec spec, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;
			this.ecSpec = spec.getParams();
			this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(ecSpec, spec.getW(), false), EC5Util.getDomainParameters(configuration, spec.getParams()));
			this.configuration = configuration;
		}

		public BCECPublicKey(string algorithm, ECPublicKeySpec spec, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;

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

			this.configuration = configuration;
		}

		public BCECPublicKey(string algorithm, ECPublicKeyParameters @params, ECParameterSpec spec, ProviderConfiguration configuration)
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

			this.configuration = configuration;
		}

		public BCECPublicKey(string algorithm, ECPublicKeyParameters @params, ECParameterSpec spec, ProviderConfiguration configuration)
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
			this.configuration = configuration;
		}

		/*
		 * called for implicitCA
		 */
		public BCECPublicKey(string algorithm, ECPublicKeyParameters @params, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;
			this.ecPublicKey = @params;
			this.ecSpec = null;
			this.configuration = configuration;
		}

		public BCECPublicKey(ECPublicKey key, ProviderConfiguration configuration)
		{
			this.algorithm = key.getAlgorithm();
			this.ecSpec = key.getParams();
			this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(this.ecSpec, key.getW(), false), EC5Util.getDomainParameters(configuration, key.getParams()));
		}

		public BCECPublicKey(string algorithm, SubjectPublicKeyInfo info, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;
			this.configuration = configuration;
			populateFromPubKeyInfo(info);
		}

		private ECParameterSpec createSpec(EllipticCurve ellipticCurve, ECDomainParameters dp)
		{
			return new ECParameterSpec(ellipticCurve, EC5Util.convertPoint(dp.getG()), dp.getN(), dp.getH().intValue());
		}

		private void populateFromPubKeyInfo(SubjectPublicKeyInfo info)
		{
			X962Parameters @params = X962Parameters.getInstance(info.getAlgorithm().getParameters());
			ECCurve curve = EC5Util.getCurve(configuration, @params);
			ecSpec = EC5Util.convertToSpec(@params, curve);

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

			this.ecPublicKey = new ECPublicKeyParameters(derQ.getPoint(), ECUtil.getDomainParameters(configuration, @params));
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
			ASN1Encodable @params = ECUtils.getDomainParametersFromName(ecSpec, withCompression);
			ASN1OctetString p = ASN1OctetString.getInstance((new X9ECPoint(ecPublicKey.getQ(), withCompression)).toASN1Primitive());

			// stored curve is null if ImplicitlyCa
			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, @params), p.getOctets());

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

			return configuration.getEcImplicitlyCa();
		}

		public override string ToString()
		{
			return ECUtil.publicKeyToString("EC", ecPublicKey.getQ(), engineGetSpec());
		}

		public virtual void setPointFormat(string style)
		{
		   withCompression = !("UNCOMPRESSED".Equals(style, StringComparison.OrdinalIgnoreCase));
		}

		public override bool Equals(object o)
		{
			if (!(o is BCECPublicKey))
			{
				return false;
			}

			BCECPublicKey other = (BCECPublicKey)o;

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

			this.configuration = BouncyCastleProvider.CONFIGURATION;

			populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(this.getEncoded());
		}
	}

}