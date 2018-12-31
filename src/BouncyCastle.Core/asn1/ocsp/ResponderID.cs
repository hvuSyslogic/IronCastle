using org.bouncycastle.asn1.x500;

namespace org.bouncycastle.asn1.ocsp
{
	
	public class ResponderID : ASN1Object, ASN1Choice
	{
		private ASN1Encodable value;

		public ResponderID(ASN1OctetString value)
		{
			this.value = value;
		}

		public ResponderID(X500Name value)
		{
			this.value = value;
		}

		public static ResponderID getInstance(object obj)
		{
			if (obj is ResponderID)
			{
				return (ResponderID)obj;
			}
			else if (obj is DEROctetString)
			{
				return new ResponderID((DEROctetString)obj);
			}
			else if (obj is ASN1TaggedObject)
			{
				ASN1TaggedObject o = (ASN1TaggedObject)obj;

				if (o.getTagNo() == 1)
				{
					return new ResponderID(X500Name.getInstance(o, true));
				}
				else
				{
					return new ResponderID(ASN1OctetString.getInstance(o, true));
				}
			}

			return new ResponderID(X500Name.getInstance(obj));
		}

		public static ResponderID getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(obj.getObject()); // must be explicitly tagged
		}

		public virtual byte[] getKeyHash()
		{
			if (this.value is ASN1OctetString)
			{
				ASN1OctetString octetString = (ASN1OctetString)this.value;
				return octetString.getOctets();
			}

			return null;
		}

		public virtual X500Name getName()
		{
			if (this.value is ASN1OctetString)
			{
				return null;
			}

			return X500Name.getInstance(value);
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// ResponderID ::= CHOICE {
		///      byName          [1] Name,
		///      byKey           [2] KeyHash }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			if (value is ASN1OctetString)
			{
				return new DERTaggedObject(true, 2, value);
			}

			return new DERTaggedObject(true, 1, value);
		}
	}

}