using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dh
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DHParameter = org.bouncycastle.asn1.pkcs.DHParameter;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DomainParameters = org.bouncycastle.asn1.x9.DomainParameters;
	using ValidationParams = org.bouncycastle.asn1.x9.ValidationParams;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPrivateKeyParameters = org.bouncycastle.crypto.@params.DHPrivateKeyParameters;
	using DHValidationParameters = org.bouncycastle.crypto.@params.DHValidationParameters;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using DHDomainParameterSpec = org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;


	public class BCDHPrivateKey : DHPrivateKey, PKCS12BagAttributeCarrier
	{
		internal const long serialVersionUID = 311058815616901812L;

		private BigInteger x;

		[NonSerialized]
		private DHParameterSpec dhSpec;
		[NonSerialized]
		private PrivateKeyInfo info;
		[NonSerialized]
		private DHPrivateKeyParameters dhPrivateKey;

		[NonSerialized]
		private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public BCDHPrivateKey()
		{
		}

		public BCDHPrivateKey(DHPrivateKey key)
		{
			this.x = key.getX();
			this.dhSpec = key.getParams();
		}

		public BCDHPrivateKey(DHPrivateKeySpec spec)
		{
			this.x = spec.getX();
			this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
		}

		public BCDHPrivateKey(PrivateKeyInfo info)
		{
			ASN1Sequence seq = ASN1Sequence.getInstance(info.getPrivateKeyAlgorithm().getParameters());
			ASN1Integer derX = (ASN1Integer)info.parsePrivateKey();
			ASN1ObjectIdentifier id = info.getPrivateKeyAlgorithm().getAlgorithm();

			this.info = info;
			this.x = derX.getValue();

			if (id.Equals(PKCSObjectIdentifiers_Fields.dhKeyAgreement))
			{
				DHParameter @params = DHParameter.getInstance(seq);

				if (@params.getL() != null)
				{
					this.dhSpec = new DHParameterSpec(@params.getP(), @params.getG(), @params.getL().intValue());
					this.dhPrivateKey = new DHPrivateKeyParameters(x, new DHParameters(@params.getP(), @params.getG(), null, @params.getL().intValue()));
				}
				else
				{
					this.dhSpec = new DHParameterSpec(@params.getP(), @params.getG());
					this.dhPrivateKey = new DHPrivateKeyParameters(x, new DHParameters(@params.getP(), @params.getG()));
				}
			}
			else if (id.Equals(X9ObjectIdentifiers_Fields.dhpublicnumber))
			{
				DomainParameters @params = DomainParameters.getInstance(seq);

				this.dhSpec = new DHDomainParameterSpec(@params.getP(), @params.getQ(), @params.getG(), @params.getJ(), 0);
				this.dhPrivateKey = new DHPrivateKeyParameters(x, new DHParameters(@params.getP(), @params.getG(), @params.getQ(), @params.getJ(), null));
			}
			else
			{
				throw new IllegalArgumentException("unknown algorithm type: " + id);
			}


		}

		public BCDHPrivateKey(DHPrivateKeyParameters @params)
		{
			this.x = @params.getX();
			this.dhSpec = new DHDomainParameterSpec(@params.getParameters());
		}

		public virtual string getAlgorithm()
		{
			return "DH";
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
			try
			{
				if (info != null)
				{
					return info.getEncoded(ASN1Encoding_Fields.DER);
				}

				PrivateKeyInfo info;
				if (dhSpec is DHDomainParameterSpec && ((DHDomainParameterSpec)dhSpec).getQ() != null)
				{
					DHParameters @params = ((DHDomainParameterSpec)dhSpec).getDomainParameters();
					DHValidationParameters validationParameters = @params.getValidationParameters();
					ValidationParams vParams = null;
					if (validationParameters != null)
					{
						vParams = new ValidationParams(validationParameters.getSeed(), validationParameters.getCounter());
					}
					info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.dhpublicnumber, (new DomainParameters(@params.getP(), @params.getG(), @params.getQ(), @params.getJ(), vParams)).toASN1Primitive()), new ASN1Integer(getX()));
				}
				else
				{
					info = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.dhKeyAgreement, (new DHParameter(dhSpec.getP(), dhSpec.getG(), dhSpec.getL())).toASN1Primitive()), new ASN1Integer(getX()));
				}
				return info.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (Exception)
			{
				return null;
			}
		}

		public override string ToString()
		{
			return DHUtil.privateKeyToString("DH", x, new DHParameters(dhSpec.getP(), dhSpec.getG()));
		}

		public virtual DHParameterSpec getParams()
		{
			return dhSpec;
		}

		public virtual BigInteger getX()
		{
			return x;
		}

		public virtual DHPrivateKeyParameters engineGetKeyParameters()
		{
			if (dhPrivateKey != null)
			{
				return dhPrivateKey;
			}

			if (dhSpec is DHDomainParameterSpec)
			{
				return new DHPrivateKeyParameters(x, ((DHDomainParameterSpec)dhSpec).getDomainParameters());
			}
			return new DHPrivateKeyParameters(x, new DHParameters(dhSpec.getP(), dhSpec.getG(), null, dhSpec.getL()));
		}

		public override bool Equals(object o)
		{
			if (!(o is DHPrivateKey))
			{
				return false;
			}

			DHPrivateKey other = (DHPrivateKey)o;

			return this.getX().Equals(other.getX()) && this.getParams().getG().Equals(other.getParams().getG()) && this.getParams().getP().Equals(other.getParams().getP()) && this.getParams().getL() == other.getParams().getL();
		}

		public override int GetHashCode()
		{
			return this.getX().GetHashCode() ^ this.getParams().getG().GetHashCode() ^ this.getParams().getP().GetHashCode() ^ this.getParams().getL();
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

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			this.dhSpec = new DHParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject(), @in.readInt());
			this.info = null;
			this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(dhSpec.getP());
			@out.writeObject(dhSpec.getG());
			@out.writeInt(dhSpec.getL());
		}
	}

}