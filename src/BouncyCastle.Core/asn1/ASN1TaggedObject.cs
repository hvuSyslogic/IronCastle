using System.IO;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// ASN.1 TaggedObject - in ASN.1 notation this is any object preceded by
	/// a [n] where n is some number - these are assumed to follow the construction
	/// rules (as with sequences).
	/// </summary>
	public abstract class ASN1TaggedObject : ASN1Primitive, ASN1TaggedObjectParser
	{
		internal int tagNo;
		internal bool empty = false;
		internal bool @explicit = true;
		internal ASN1Encodable obj = null;

		public static ASN1TaggedObject getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			if (@explicit)
			{
				return (ASN1TaggedObject)obj.getObject();
			}

			throw new IllegalArgumentException("implicitly tagged tagged object");
		}

		public static ASN1TaggedObject getInstance(object obj)
		{
			if (obj == null || obj is ASN1TaggedObject)
			{
					return (ASN1TaggedObject)obj;
			}
			else if (obj is byte[])
			{
				try
				{
					return ASN1TaggedObject.getInstance(fromByteArray((byte[])obj));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("failed to construct tagged object from byte[]: " + e.Message);
				}
			}

			throw new IllegalArgumentException("unknown object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Create a tagged object with the style given by the value of explicit.
		/// <para>
		/// If the object implements ASN1Choice the tag style will always be changed
		/// to explicit in accordance with the ASN.1 encoding rules.
		/// </para> </summary>
		/// <param name="explicit"> true if the object is explicitly tagged. </param>
		/// <param name="tagNo"> the tag number for this object. </param>
		/// <param name="obj"> the tagged object. </param>
		public ASN1TaggedObject(bool @explicit, int tagNo, ASN1Encodable obj)
		{
			if (obj is ASN1Choice)
			{
				this.@explicit = true;
			}
			else
			{
				this.@explicit = @explicit;
			}

			this.tagNo = tagNo;

			if (this.@explicit)
			{
				this.obj = obj;
			}
			else
			{
				ASN1Primitive prim = obj.toASN1Primitive();

				if (prim is ASN1Set)
				{
					ASN1Set s = null;
				}

				this.obj = obj;
			}
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1TaggedObject))
			{
				return false;
			}

			ASN1TaggedObject other = (ASN1TaggedObject)o;

			if (tagNo != other.tagNo || empty != other.empty || @explicit != other.@explicit)
			{
				return false;
			}

			if (obj == null)
			{
				if (other.obj != null)
				{
					return false;
				}
			}
			else
			{
				if (!(obj.toASN1Primitive().Equals(other.obj.toASN1Primitive())))
				{
					return false;
				}
			}

			return true;
		}

		public override int GetHashCode()
		{
			int code = tagNo;

			// TODO: actually this is wrong - the problem is that a re-encoded
			// object may end up with a different hashCode due to implicit
			// tagging. As implicit tagging is ambiguous if a sequence is involved
			// it seems the only correct method for both equals and hashCode is to
			// compare the encodings...
			if (obj != null)
			{
				code ^= obj.GetHashCode();
			}

			return code;
		}

		/// <summary>
		/// Return the tag number associated with this object.
		/// </summary>
		/// <returns> the tag number. </returns>
		public virtual int getTagNo()
		{
			return tagNo;
		}

		/// <summary>
		/// return whether or not the object may be explicitly tagged. 
		/// <para>
		/// Note: if the object has been read from an input stream, the only
		/// time you can be sure if isExplicit is returning the true state of
		/// affairs is if it returns false. An implicitly tagged object may appear
		/// to be explicitly tagged, so you need to understand the context under
		/// which the reading was done as well, see getObject below.
		/// </para>
		/// </summary>
		public virtual bool isExplicit()
		{
			return @explicit;
		}

		public virtual bool isEmpty()
		{
			return empty;
		}

		/// <summary>
		/// Return whatever was following the tag.
		/// <para>
		/// Note: tagged objects are generally context dependent if you're
		/// trying to extract a tagged object you should be going via the
		/// appropriate getInstance method.
		/// </para>
		/// </summary>
		public virtual ASN1Primitive getObject()
		{
			if (obj != null)
			{
				return obj.toASN1Primitive();
			}

			return null;
		}

		/// <summary>
		/// Return the object held in this tagged object as a parser assuming it has
		/// the type of the passed in tag. If the object doesn't have a parser
		/// associated with it, the base object is returned.
		/// </summary>
		public virtual ASN1Encodable getObjectParser(int tag, bool isExplicit)
		{
			switch (tag)
			{
			case BERTags_Fields.SET:
				return ASN1Set.getInstance(this, isExplicit).parser();
			case BERTags_Fields.SEQUENCE:
				return ASN1Sequence.getInstance(this, isExplicit).parser();
			case BERTags_Fields.OCTET_STRING:
				return ASN1OctetString.getInstance(this, isExplicit).parser();
			}

			if (isExplicit)
			{
				return getObject();
			}

			throw new ASN1Exception("implicit tagging not implemented for tag: " + tag);
		}

		public virtual ASN1Primitive getLoadedObject()
		{
			return this.toASN1Primitive();
		}

		public override ASN1Primitive toDERObject()
		{
			return new DERTaggedObject(@explicit, tagNo, obj);
		}

		public override ASN1Primitive toDLObject()
		{
			return new DLTaggedObject(@explicit, tagNo, obj);
		}

		public override abstract void encode(ASN1OutputStream @out);

		public override string ToString()
		{
			return "[" + tagNo + "]" + obj;
		}
	}

}