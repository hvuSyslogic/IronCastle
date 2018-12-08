using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;

namespace org.bouncycastle.jce.provider
{


	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DHParameter = org.bouncycastle.asn1.pkcs.DHParameter;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DHDomainParameters = org.bouncycastle.asn1.x9.DHDomainParameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;

	public class JCEDHPublicKey : DHPublicKey
	{
		internal const long serialVersionUID = -216691575254424324L;

		private BigInteger y;
		private DHParameterSpec dhSpec;
		private SubjectPublicKeyInfo info;

		public JCEDHPublicKey(DHPublicKeySpec spec)
		{
			this.y = spec.getY();
			this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
		}

		public JCEDHPublicKey(DHPublicKey key)
		{
			this.y = key.getY();
			this.dhSpec = key.getParams();
		}

		public JCEDHPublicKey(DHPublicKeyParameters @params)
		{
			this.y = @params.getY();
			this.dhSpec = new DHParameterSpec(@params.getParameters().getP(), @params.getParameters().getG(), @params.getParameters().getL());
		}

		public JCEDHPublicKey(BigInteger y, DHParameterSpec dhSpec)
		{
			this.y = y;
			this.dhSpec = dhSpec;
		}

		public JCEDHPublicKey(SubjectPublicKeyInfo info)
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

			ASN1Sequence seq = ASN1Sequence.getInstance(info.getAlgorithmId().getParameters());
			ASN1ObjectIdentifier id = info.getAlgorithmId().getAlgorithm();

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
			}
			else if (id.Equals(X9ObjectIdentifiers_Fields.dhpublicnumber))
			{
				DHDomainParameters @params = DHDomainParameters.getInstance(seq);

				this.dhSpec = new DHParameterSpec(@params.getP().getValue(), @params.getG().getValue());
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

			return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.dhKeyAgreement, new DHParameter(dhSpec.getP(), dhSpec.getG(), dhSpec.getL())), new ASN1Integer(y));
		}

		public virtual DHParameterSpec getParams()
		{
			return dhSpec;
		}

		public virtual BigInteger getY()
		{
			return y;
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

		private void readObject(ObjectInputStream @in)
		{
			this.y = (BigInteger)@in.readObject();
			this.dhSpec = new DHParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject(), @in.readInt());
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.writeObject(this.getY());
			@out.writeObject(dhSpec.getP());
			@out.writeObject(dhSpec.getG());
			@out.writeInt(dhSpec.getL());
		}
	}

}