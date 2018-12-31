namespace org.bouncycastle.asn1.crmf
{
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	public class EncKeyWithID : ASN1Object
	{
		private readonly PrivateKeyInfo privKeyInfo;
		private readonly ASN1Encodable identifier;

		public static EncKeyWithID getInstance(object o)
		{
			if (o is EncKeyWithID)
			{
				return (EncKeyWithID)o;
			}
			else if (o != null)
			{
				return new EncKeyWithID(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private EncKeyWithID(ASN1Sequence seq)
		{
			this.privKeyInfo = PrivateKeyInfo.getInstance(seq.getObjectAt(0));

			if (seq.size() > 1)
			{
				if (!(seq.getObjectAt(1) is DERUTF8String))
				{
					this.identifier = GeneralName.getInstance(seq.getObjectAt(1));
				}
				else
				{
					this.identifier = seq.getObjectAt(1);
				}
			}
			else
			{
				this.identifier = null;
			}
		}

		public EncKeyWithID(PrivateKeyInfo privKeyInfo)
		{
			this.privKeyInfo = privKeyInfo;
			this.identifier = null;
		}

		public EncKeyWithID(PrivateKeyInfo privKeyInfo, DERUTF8String str)
		{
			this.privKeyInfo = privKeyInfo;
			this.identifier = str;
		}

		public EncKeyWithID(PrivateKeyInfo privKeyInfo, GeneralName generalName)
		{
			this.privKeyInfo = privKeyInfo;
			this.identifier = generalName;
		}

		public virtual PrivateKeyInfo getPrivateKey()
		{
			return privKeyInfo;
		}

		public virtual bool hasIdentifier()
		{
			return identifier != null;
		}

		public virtual bool isIdentifierUTF8String()
		{
			return identifier is DERUTF8String;
		}

		public virtual ASN1Encodable getIdentifier()
		{
			return identifier;
		}

		/// <summary>
		/// <pre>
		/// EncKeyWithID ::= SEQUENCE {
		///      privateKey           PrivateKeyInfo,
		///      identifier CHOICE {
		///         string               UTF8String,
		///         generalName          GeneralName
		///     } OPTIONAL
		/// }
		/// </pre> </summary>
		/// <returns> an ASN.1 primitive composition of this EncKeyWithID. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(privKeyInfo);

			if (identifier != null)
			{
				v.add(identifier);
			}

			return new DERSequence(v);
		}
	}

}