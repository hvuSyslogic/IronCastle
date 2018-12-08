using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.pkcs
{


	public class RC2CBCParameter : ASN1Object
	{
		internal ASN1Integer version;
		internal ASN1OctetString iv;

		public static RC2CBCParameter getInstance(object o)
		{
			if (o is RC2CBCParameter)
			{
				return (RC2CBCParameter)o;
			}
			if (o != null)
			{
				return new RC2CBCParameter(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public RC2CBCParameter(byte[] iv)
		{
			this.version = null;
			this.iv = new DEROctetString(iv);
		}

		public RC2CBCParameter(int parameterVersion, byte[] iv)
		{
			this.version = new ASN1Integer(parameterVersion);
			this.iv = new DEROctetString(iv);
		}

		private RC2CBCParameter(ASN1Sequence seq)
		{
			if (seq.size() == 1)
			{
				version = null;
				iv = (ASN1OctetString)seq.getObjectAt(0);
			}
			else
			{
				version = (ASN1Integer)seq.getObjectAt(0);
				iv = (ASN1OctetString)seq.getObjectAt(1);
			}
		}

		public virtual BigInteger getRC2ParameterVersion()
		{
			if (version == null)
			{
				return null;
			}

			return version.getValue();
		}

		public virtual byte[] getIV()
		{
			return iv.getOctets();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (version != null)
			{
				v.add(version);
			}

			v.add(iv);

			return new DERSequence(v);
		}
	}

}