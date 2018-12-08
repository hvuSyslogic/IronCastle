using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dh
{


	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DHParameter = org.bouncycastle.asn1.pkcs.DHParameter;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DomainParameters = org.bouncycastle.asn1.x9.DomainParameters;
	using ValidationParams = org.bouncycastle.asn1.x9.ValidationParams;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using DHValidationParameters = org.bouncycastle.crypto.@params.DHValidationParameters;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using DHDomainParameterSpec = org.bouncycastle.jcajce.spec.DHDomainParameterSpec;

	public class BCDHPublicKey : DHPublicKey
	{
		internal const long serialVersionUID = -216691575254424324L;

		private BigInteger y;

		[NonSerialized]
		private DHPublicKeyParameters dhPublicKey;
		[NonSerialized]
		private DHParameterSpec dhSpec;
		[NonSerialized]
		private SubjectPublicKeyInfo info;

		public BCDHPublicKey(DHPublicKeySpec spec)
		{
			this.y = spec.getY();
			this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
			this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(spec.getP(), spec.getG()));
		}

		public BCDHPublicKey(DHPublicKey key)
		{
			this.y = key.getY();
			this.dhSpec = key.getParams();
			this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
		}

		public BCDHPublicKey(DHPublicKeyParameters @params)
		{
			this.y = @params.getY();
			this.dhSpec = new DHDomainParameterSpec(@params.getParameters());
			this.dhPublicKey = @params;
		}

		public BCDHPublicKey(BigInteger y, DHParameterSpec dhSpec)
		{
			this.y = y;
			this.dhSpec = dhSpec;

			if (dhSpec is DHDomainParameterSpec)
			{
				this.dhPublicKey = new DHPublicKeyParameters(y, ((DHDomainParameterSpec)dhSpec).getDomainParameters());
			}
			else
			{
				this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
			}
		}

		public BCDHPublicKey(SubjectPublicKeyInfo info)
		{
			this.info = info;

			ASN1Integer derY;
			try
			{
				derY = (ASN1Integer)info.parsePublicKey();
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("invalid info structure in DH public key");
			}

			this.y = derY.getValue();

			ASN1Sequence seq = ASN1Sequence.getInstance(info.getAlgorithm().getParameters());
			ASN1ObjectIdentifier id = info.getAlgorithm().getAlgorithm();

			// we need the PKCS check to handle older keys marked with the X9 oid.
			if (id.Equals(PKCSObjectIdentifiers_Fields.dhKeyAgreement) || isPKCSParam(seq))
			{
				DHParameter @params = DHParameter.getInstance(seq);

				if (@params.getL() != null)
				{
					this.dhSpec = new DHParameterSpec(@params.getP(), @params.getG(), @params.getL().intValue());
				}
				else
				{
					this.dhSpec = new DHParameterSpec(@params.getP(), @params.getG());
				}
				this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
			}
			else if (id.Equals(X9ObjectIdentifiers_Fields.dhpublicnumber))
			{
				DomainParameters @params = DomainParameters.getInstance(seq);

				ValidationParams validationParams = @params.getValidationParams();
				if (validationParams != null)
				{
					this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(@params.getP(), @params.getG(), @params.getQ(), @params.getJ(), new DHValidationParameters(validationParams.getSeed(), validationParams.getPgenCounter().intValue())));
				}
				else
				{
					this.dhPublicKey = new DHPublicKeyParameters(y, new DHParameters(@params.getP(), @params.getG(), @params.getQ(), @params.getJ(), null));
				}
				this.dhSpec = new DHDomainParameterSpec(dhPublicKey.getParameters());
			}
			else
			{
				throw new IllegalArgumentException("unknown algorithm type: " + id);
			}
		}

		public virtual string getAlgorithm()
		{
			return "DH";
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getEncoded()
		{
			if (info != null)
			{
				return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
			}

			if (dhSpec is DHDomainParameterSpec && ((DHDomainParameterSpec)dhSpec).getQ() != null)
			{
				DHParameters @params = ((DHDomainParameterSpec)dhSpec).getDomainParameters();
				DHValidationParameters validationParameters = @params.getValidationParameters();
				ValidationParams vParams = null;
				if (validationParameters != null)
				{
					vParams = new ValidationParams(validationParameters.getSeed(), validationParameters.getCounter());
				}
				return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.dhpublicnumber, (new DomainParameters(@params.getP(), @params.getG(), @params.getQ(), @params.getJ(), vParams)).toASN1Primitive()), new ASN1Integer(y));
			}
			return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.dhKeyAgreement, (new DHParameter(dhSpec.getP(), dhSpec.getG(), dhSpec.getL())).toASN1Primitive()), new ASN1Integer(y));
		}

		public override string ToString()
		{
			return DHUtil.publicKeyToString("DH", y, new DHParameters(dhSpec.getP(), dhSpec.getG()));
		}

		public virtual DHParameterSpec getParams()
		{
			return dhSpec;
		}

		public virtual BigInteger getY()
		{
			return y;
		}

		public virtual DHPublicKeyParameters engineGetKeyParameters()
		{
			return dhPublicKey;
		}

		private bool isPKCSParam(ASN1Sequence seq)
		{
			if (seq.size() == 2)
			{
				return true;
			}

			if (seq.size() > 3)
			{
				return false;
			}

			ASN1Integer l = ASN1Integer.getInstance(seq.getObjectAt(2));
			ASN1Integer p = ASN1Integer.getInstance(seq.getObjectAt(0));

			if (l.getValue().compareTo(BigInteger.valueOf(p.getValue().bitLength())) > 0)
			{
				return false;
			}

			return true;
		}

		public override int GetHashCode()
		{
			return this.getY().GetHashCode() ^ this.getParams().getG().GetHashCode() ^ this.getParams().getP().GetHashCode() ^ this.getParams().getL();
		}

		public override bool Equals(object o)
		{
			if (!(o is DHPublicKey))
			{
				return false;
			}

			DHPublicKey other = (DHPublicKey)o;

			return this.getY().Equals(other.getY()) && this.getParams().getG().Equals(other.getParams().getG()) && this.getParams().getP().Equals(other.getParams().getP()) && this.getParams().getL() == other.getParams().getL();
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			this.dhSpec = new DHParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject(), @in.readInt());
			this.info = null;
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