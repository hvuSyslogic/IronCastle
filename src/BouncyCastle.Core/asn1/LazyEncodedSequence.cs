using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Note: this class is for processing DER/DL encoded sequences only.
	/// </summary>
	public class LazyEncodedSequence : ASN1Sequence
	{
		private byte[] encoded;

		public LazyEncodedSequence(byte[] encoded)
		{
			this.encoded = encoded;
		}

		private void parse()
		{
			Enumeration en = new LazyConstructionEnumeration(encoded);

			while (en.hasMoreElements())
			{
				seq.addElement(en.nextElement());
			}

			encoded = null;
		}

		public override ASN1Encodable getObjectAt(int index)
		{
			lock (this)
			{
				if (encoded != null)
				{
					parse();
				}
        
				return base.getObjectAt(index);
			}
		}

		public override Enumeration getObjects()
		{
			lock (this)
			{
				if (encoded == null)
				{
					return base.getObjects();
				}
        
				return new LazyConstructionEnumeration(encoded);
			}
		}

		public override int size()
		{
			lock (this)
			{
				if (encoded != null)
				{
					parse();
				}
        
				return base.size();
			}
		}

		public override ASN1Primitive toDERObject()
		{
			if (encoded != null)
			{
				parse();
			}

			return base.toDERObject();
		}

		public override ASN1Primitive toDLObject()
		{
			if (encoded != null)
			{
				parse();
			}

			return base.toDLObject();
		}

		public override int encodedLength()
		{
			if (encoded != null)
			{
				return 1 + StreamUtil.calculateBodyLength(encoded.Length) + encoded.Length;
			}
			else
			{
				return base.toDLObject().encodedLength();
			}
		}

		public override void encode(ASN1OutputStream @out)
		{
			if (encoded != null)
			{
				@out.writeEncoded(BERTags_Fields.SEQUENCE | BERTags_Fields.CONSTRUCTED, encoded);
			}
			else
			{
				base.toDLObject().encode(@out);
			}
		}
	}

}