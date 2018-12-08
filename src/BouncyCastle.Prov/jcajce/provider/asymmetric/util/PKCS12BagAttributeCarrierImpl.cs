namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OutputStream = org.bouncycastle.asn1.ASN1OutputStream;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;

	public class PKCS12BagAttributeCarrierImpl : PKCS12BagAttributeCarrier
	{
		private Hashtable pkcs12Attributes;
		private Vector pkcs12Ordering;

		public PKCS12BagAttributeCarrierImpl(Hashtable attributes, Vector ordering)
		{
			this.pkcs12Attributes = attributes;
			this.pkcs12Ordering = ordering;
		}

		public PKCS12BagAttributeCarrierImpl() : this(new Hashtable(), new Vector())
		{
		}

		public virtual void setBagAttribute(ASN1ObjectIdentifier oid, ASN1Encodable attribute)
		{
			if (pkcs12Attributes.containsKey(oid))
			{ // preserve original ordering
				pkcs12Attributes.put(oid, attribute);
			}
			else
			{
				pkcs12Attributes.put(oid, attribute);
				pkcs12Ordering.addElement(oid);
			}
		}

		public virtual ASN1Encodable getBagAttribute(ASN1ObjectIdentifier oid)
		{
			return (ASN1Encodable)pkcs12Attributes.get(oid);
		}

		public virtual Enumeration getBagAttributeKeys()
		{
			return pkcs12Ordering.elements();
		}

		public virtual int size()
		{
			return pkcs12Ordering.size();
		}

		public virtual Hashtable getAttributes()
		{
			return pkcs12Attributes;
		}

		public virtual Vector getOrdering()
		{
			return pkcs12Ordering;
		}

		public virtual void writeObject(ObjectOutputStream @out)
		{
			if (pkcs12Ordering.size() == 0)
			{
				@out.writeObject(new Hashtable());
				@out.writeObject(new Vector());
			}
			else
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				ASN1OutputStream aOut = new ASN1OutputStream(bOut);

				Enumeration e = this.getBagAttributeKeys();

				while (e.hasMoreElements())
				{
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();

					aOut.writeObject(oid);
					aOut.writeObject((ASN1Encodable)pkcs12Attributes.get(oid));
				}

				@out.writeObject(bOut.toByteArray());
			}
		}

		public virtual void readObject(ObjectInputStream @in)
		{
			object obj = @in.readObject();

			if (obj is Hashtable)
			{
				this.pkcs12Attributes = (Hashtable)obj;
				this.pkcs12Ordering = (Vector)@in.readObject();
			}
			else
			{
				ASN1InputStream aIn = new ASN1InputStream((byte[])obj);

				ASN1ObjectIdentifier oid;

				while ((oid = (ASN1ObjectIdentifier)aIn.readObject()) != null)
				{
					this.setBagAttribute(oid, aIn.readObject());
				}
			}
		}
	}

}