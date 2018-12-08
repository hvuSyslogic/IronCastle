using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// ASN.1 <code>SEQUENCE</code> and <code>SEQUENCE OF</code> constructs.
	/// <para>
	/// DER form is always definite form length fields, while
	/// BER support uses indefinite form.
	/// <hr>
	/// </para>
	/// <para><b>X.690</b></para>
	/// <para><b>8: Basic encoding rules</b></para>
	/// <para><b>8.9 Encoding of a sequence value </b></para>
	/// 8.9.1 The encoding of a sequence value shall be constructed.
	/// <para>
	/// <b>8.9.2</b> The contents octets shall consist of the complete
	/// encoding of one data value from each of the types listed in
	/// the ASN.1 definition of the sequence type, in the order of
	/// their appearance in the definition, unless the type was referenced
	/// with the keyword <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
	/// </para>
	/// </para><para>
	/// <b>8.9.3</b> The encoding of a data value may, but need not,
	/// be present for a type which was referenced with the keyword
	/// <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
	/// If present, it shall appear in the encoding at the point
	/// corresponding to the appearance of the type in the ASN.1 definition.
	/// </para><para>
	/// <b>8.10 Encoding of a sequence-of value </b>
	/// </para><para>
	/// <b>8.10.1</b> The encoding of a sequence-of value shall be constructed.
	/// <para>
	/// <b>8.10.2</b> The contents octets shall consist of zero,
	/// one or more complete encodings of data values from the type listed in
	/// the ASN.1 definition.
	/// </para>
	/// <para>
	/// <b>8.10.3</b> The order of the encodings of the data values shall be
	/// the same as the order of the data values in the sequence-of value to
	/// be encoded.
	/// </para>
	/// <para><b>9: Canonical encoding rules</b></para>
	/// <para><b>9.1 Length forms</b></para>
	/// If the encoding is constructed, it shall employ the indefinite-length form.
	/// If the encoding is primitive, it shall include the fewest length octets necessary.
	/// [Contrast with 8.1.3.2 b).]
	/// 
	/// <para><b>11: Restrictions on BER employed by both CER and DER</b></para>
	/// <para><b>11.5 Set and sequence components with default value</b></para>
	/// <para>
	/// The encoding of a set value or sequence value shall not include
	/// an encoding for any component value which is equal to
	/// its default value.
	/// </para>
	/// </summary>
	public abstract class ASN1Sequence : ASN1Primitive, bouncycastle.util.Iterable<ASN1Encodable>
	{
		protected internal Vector seq = new Vector();

		/// <summary>
		/// Return an ASN1Sequence from the given object.
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="Port.java.lang.IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> an ASN1Sequence instance, or null. </returns>
		public static ASN1Sequence getInstance(object obj)
		{
			if (obj == null || obj is ASN1Sequence)
			{
				return (ASN1Sequence)obj;
			}
			else if (obj is ASN1SequenceParser)
			{
				return ASN1Sequence.getInstance(((ASN1SequenceParser)obj).toASN1Primitive());
			}
			else if (obj is byte[])
			{
				try
				{
					return ASN1Sequence.getInstance(fromByteArray((byte[])obj));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("failed to construct sequence from byte[]: " + e.Message);
				}
			}
			else if (obj is ASN1Encodable)
			{
				ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

				if (primitive is ASN1Sequence)
				{
					return (ASN1Sequence)primitive;
				}
			}

			throw new IllegalArgumentException("unknown object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an ASN1 SEQUENCE from a tagged object. There is a special
		/// case here, if an object appears to have been explicitly tagged on 
		/// reading but we were expecting it to be implicitly tagged in the 
		/// normal course of events it indicates that we lost the surrounding
		/// sequence - so we need to add it back (this will happen if the tagged
		/// object is a sequence that contains other sequences). If you are
		/// dealing with implicitly tagged sequences you really <b>should</b>
		/// be using this method.
		/// </summary>
		/// <param name="obj"> the tagged object. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly tagged,
		///          false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///          be converted. </exception>
		/// <returns> an ASN1Sequence instance. </returns>
		public static ASN1Sequence getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			if (@explicit)
			{
				if (!obj.isExplicit())
				{
					throw new IllegalArgumentException("object implicit - explicit expected.");
				}

				return ASN1Sequence.getInstance(obj.getObject().toASN1Primitive());
			}
			else
			{
				ASN1Primitive o = obj.getObject();

				//
				// constructed object which appears to be explicitly tagged
				// when it should be implicit means we have to add the
				// surrounding sequence.
				//
				if (obj.isExplicit())
				{
					if (obj is BERTaggedObject)
					{
						return new BERSequence(o);
					}
					else
					{
						return new DLSequence(o);
					}
				}
				else
				{
					if (o is ASN1Sequence)
					{
						return (ASN1Sequence)o;
					}
				}
			}

			throw new IllegalArgumentException("unknown object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Create an empty SEQUENCE
		/// </summary>
		public ASN1Sequence()
		{
		}

		/// <summary>
		/// Create a SEQUENCE containing one object. </summary>
		/// <param name="obj"> the object to be put in the SEQUENCE. </param>
		public ASN1Sequence(ASN1Encodable obj)
		{
			seq.addElement(obj);
		}

		/// <summary>
		/// Create a SEQUENCE containing a vector of objects. </summary>
		/// <param name="v"> the vector of objects to be put in the SEQUENCE. </param>
		public ASN1Sequence(ASN1EncodableVector v)
		{
			for (int i = 0; i != v.size(); i++)
			{
				seq.addElement(v.get(i));
			}
		}

		/// <summary>
		/// Create a SEQUENCE containing an array of objects. </summary>
		/// <param name="array"> the array of objects to be put in the SEQUENCE. </param>
		public ASN1Sequence(ASN1Encodable[] array)
		{
			for (int i = 0; i != array.Length; i++)
			{
				seq.addElement(array[i]);
			}
		}

		public virtual ASN1Encodable[] toArray()
		{
			ASN1Encodable[] values = new ASN1Encodable[this.size()];

			for (int i = 0; i != this.size(); i++)
			{
				values[i] = this.getObjectAt(i);
			}

			return values;
		}

		public virtual Enumeration getObjects()
		{
			return seq.elements();
		}

		public virtual ASN1SequenceParser parser()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final ASN1Sequence outer = this;
			ASN1Sequence outer = this;

			return new ASN1SequenceParserAnonymousInnerClass(this, outer);
		}

		public class ASN1SequenceParserAnonymousInnerClass : ASN1SequenceParser
		{
			private readonly ASN1Sequence outerInstance;

			private ASN1Sequence outer;

			public ASN1SequenceParserAnonymousInnerClass(ASN1Sequence outerInstance, ASN1Sequence outer)
			{
				this.outerInstance = outerInstance;
				this.outer = outer;
				max = outerInstance.size();
			}

			private readonly int max;

			private int index;

			public ASN1Encodable readObject()
			{
				if (index == max)
				{
					return null;
				}

				ASN1Encodable obj = outerInstance.getObjectAt(index++);
				if (obj is ASN1Sequence)
				{
					return ((ASN1Sequence)obj).parser();
				}
				if (obj is ASN1Set)
				{
					return ((ASN1Set)obj).parser();
				}

				return obj;
			}

			public ASN1Primitive getLoadedObject()
			{
				return outer;
			}

			public ASN1Primitive toASN1Primitive()
			{
				return outer;
			}
		}

		/// <summary>
		/// Return the object at the sequence position indicated by index.
		/// </summary>
		/// <param name="index"> the sequence number (starting at zero) of the object </param>
		/// <returns> the object at the sequence position indicated by index. </returns>
		public virtual ASN1Encodable getObjectAt(int index)
		{
			return (ASN1Encodable)seq.elementAt(index);
		}

		/// <summary>
		/// Return the number of objects in this sequence.
		/// </summary>
		/// <returns> the number of objects in this sequence. </returns>
		public virtual int size()
		{
			return seq.size();
		}

		public override int GetHashCode()
		{
			Enumeration e = this.getObjects();
			int hashCode = size();

			while (e.hasMoreElements())
			{
				object o = getNext(e);
				hashCode *= 17;

				hashCode ^= o.GetHashCode();
			}

			return hashCode;
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1Sequence))
			{
				return false;
			}

			ASN1Sequence other = (ASN1Sequence)o;

			if (this.size() != other.size())
			{
				return false;
			}

			Enumeration s1 = this.getObjects();
			Enumeration s2 = other.getObjects();

			while (s1.hasMoreElements())
			{
				ASN1Encodable obj1 = getNext(s1);
				ASN1Encodable obj2 = getNext(s2);

				ASN1Primitive o1 = obj1.toASN1Primitive();
				ASN1Primitive o2 = obj2.toASN1Primitive();

				if (o1 == o2 || o1.Equals(o2))
				{
					continue;
				}

				return false;
			}

			return true;
		}

		private ASN1Encodable getNext(Enumeration e)
		{
			ASN1Encodable encObj = (ASN1Encodable)e.nextElement();

			return encObj;
		}

		/// <summary>
		/// Change current SEQUENCE object to be encoded as <seealso cref="DERSequence"/>.
		/// This is part of Distinguished Encoding Rules form serialization.
		/// </summary>
		public override ASN1Primitive toDERObject()
		{
			ASN1Sequence derSeq = new DERSequence();

			derSeq.seq = this.seq;

			return derSeq;
		}

		/// <summary>
		/// Change current SEQUENCE object to be encoded as <seealso cref="DLSequence"/>.
		/// This is part of Direct Length form serialization.
		/// </summary>
		public override ASN1Primitive toDLObject()
		{
			ASN1Sequence dlSeq = new DLSequence();

			dlSeq.seq = this.seq;

			return dlSeq;
		}

		public override bool isConstructed()
		{
			return true;
		}

		public override abstract void encode(ASN1OutputStream @out);

		public override string ToString()
		{
			return seq.ToString();
		}

		public virtual Iterator<ASN1Encodable> iterator()
		{
			return new Arrays.Iterator<ASN1Encodable>(toArray());
		}
	}

}