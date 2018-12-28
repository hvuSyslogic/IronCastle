using System;
using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// ASN.1 <code>SET</code> and <code>SET OF</code> constructs.
	/// <para>
	/// Note: This does not know which syntax the set is!
	/// (The difference: ordering of SET elements or not ordering.)
	/// </para>
	/// </para><para>
	/// DER form is always definite form length fields, while
	/// BER support uses indefinite form.
	/// </para><para>
	/// The CER form support does not exist.
	/// </para><para>
	/// <h2>X.690</h2>
	/// <h3>8: Basic encoding rules</h3>
	/// <h4>8.11 Encoding of a set value </h4>
	/// <b>8.11.1</b> The encoding of a set value shall be constructed
	/// <para>
	/// <b>8.11.2</b> The contents octets shall consist of the complete
	/// encoding of a data value from each of the types listed in the
	/// ASN.1 definition of the set type, in an order chosen by the sender,
	/// unless the type was referenced with the keyword
	/// <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
	/// </para>
	/// </para><para>
	/// <b>8.11.3</b> The encoding of a data value may, but need not,
	/// be present for a type which was referenced with the keyword
	/// <b>OPTIONAL</b> or the keyword <b>DEFAULT</b>.
	/// <blockquote>
	/// NOTE &mdash; The order of data values in a set value is not significant,
	/// and places no constraints on the order during transfer
	/// </blockquote>
	/// <h4>8.12 Encoding of a set-of value</h4>
	/// <para>
	/// <b>8.12.1</b> The encoding of a set-of value shall be constructed.
	/// </para>
	/// </para><para>
	/// <b>8.12.2</b> The text of 8.10.2 applies:
	/// <i>The contents octets shall consist of zero,
	/// one or more complete encodings of data values from the type listed in
	/// the ASN.1 definition.</i>
	/// </para><para>
	/// <b>8.12.3</b> The order of data values need not be preserved by
	/// the encoding and subsequent decoding.
	/// 
	/// <h3>9: Canonical encoding rules</h3>
	/// <h4>9.1 Length forms</h4>
	/// If the encoding is constructed, it shall employ the indefinite-length form.
	/// If the encoding is primitive, it shall include the fewest length octets necessary.
	/// [Contrast with 8.1.3.2 b).]
	/// <h4>9.3 Set components</h4>
	/// The encodings of the component values of a set value shall
	/// appear in an order determined by their tags as specified
	/// in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
	/// Additionally, for the purposes of determining the order in which
	/// components are encoded when one or more component is an untagged
	/// choice type, each untagged choice type is ordered as though it
	/// has a tag equal to that of the smallest tag in that choice type
	/// or any untagged choice types nested within.
	/// 
	/// <h3>10: Distinguished encoding rules</h3>
	/// <h4>10.1 Length forms</h4>
	/// The definite form of length encoding shall be used,
	/// encoded in the minimum number of octets.
	/// [Contrast with 8.1.3.2 b).]
	/// <h4>10.3 Set components</h4>
	/// The encodings of the component values of a set value shall appear
	/// in an order determined by their tags as specified
	/// in 8.6 of ITU-T Rec. X.680 | ISO/IEC 8824-1.
	/// <blockquote>
	/// NOTE &mdash; Where a component of the set is an untagged choice type,
	/// the location of that component in the ordering will depend on
	/// the tag of the choice component being encoded.
	/// </blockquote>
	/// 
	/// <h3>11: Restrictions on BER employed by both CER and DER</h3>
	/// <h4>11.5 Set and sequence components with default value </h4>
	/// The encoding of a set value or sequence value shall not include
	/// an encoding for any component value which is equal to
	/// its default value.
	/// <h4>11.6 Set-of components </h4>
	/// <para>
	/// The encodings of the component values of a set-of value
	/// shall appear in ascending order, the encodings being compared
	/// as octet strings with the shorter components being padded at
	/// their trailing end with 0-octets.
	/// <blockquote>
	/// NOTE &mdash; The padding octets are for comparison purposes only
	/// and do not appear in the encodings.
	/// </blockquote>
	/// </para>
	/// </summary>
	public abstract class ASN1Set : ASN1Primitive, Iterable<ASN1Encodable>
	{
		private Vector set = new Vector();
		private bool isSorted = false;

		/// <summary>
		/// return an ASN1Set from the given object.
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="Port.java.lang.IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> an ASN1Set instance, or null. </returns>
		public static ASN1Set getInstance(object obj)
		{
			if (obj == null || obj is ASN1Set)
			{
				return (ASN1Set)obj;
			}
			else if (obj is ASN1SetParser)
			{
				return ASN1Set.getInstance(((ASN1SetParser)obj).toASN1Primitive());
			}
			else if (obj is byte[])
			{
				try
				{
					return ASN1Set.getInstance(ASN1Primitive.fromByteArray((byte[])obj));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("failed to construct set from byte[]: " + e.Message);
				}
			}
			else if (obj is ASN1Encodable)
			{
				ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();

				if (primitive is ASN1Set)
				{
					return (ASN1Set)primitive;
				}
			}

			throw new IllegalArgumentException("unknown object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an ASN1 set from a tagged object. There is a special
		/// case here, if an object appears to have been explicitly tagged on 
		/// reading but we were expecting it to be implicitly tagged in the 
		/// normal course of events it indicates that we lost the surrounding
		/// set - so we need to add it back (this will happen if the tagged
		/// object is a sequence that contains other sequences). If you are
		/// dealing with implicitly tagged sets you really <b>should</b>
		/// be using this method.
		/// </summary>
		/// <param name="obj"> the tagged object. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly tagged
		///          false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///          be converted. </exception>
		/// <returns> an ASN1Set instance. </returns>
		public static ASN1Set getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			if (@explicit)
			{
				if (!obj.isExplicit())
				{
					throw new IllegalArgumentException("object implicit - explicit expected.");
				}

				return (ASN1Set)obj.getObject();
			}
			else
			{
				ASN1Primitive o = obj.getObject();

				//
				// constructed object which appears to be explicitly tagged
				// and it's really implicit means we have to add the
				// surrounding set.
				//
				if (obj.isExplicit())
				{
					if (obj is BERTaggedObject)
					{
						return new BERSet(o);
					}
					else
					{
						return new DLSet(o);
					}
				}
				else
				{
					if (o is ASN1Set)
					{
						return (ASN1Set)o;
					}

					//
					// in this case the parser returns a sequence, convert it
					// into a set.
					//
					if (o is ASN1Sequence)
					{
						ASN1Sequence s = (ASN1Sequence)o;

						if (obj is BERTaggedObject)
						{
							return new BERSet(s.toArray());
						}
						else
						{
							return new DLSet(s.toArray());
						}
					}
				}
			}

			throw new IllegalArgumentException("unknown object in getInstance: " + obj.GetType().getName());
		}

		public ASN1Set()
		{
		}

		/// <summary>
		/// Create a SET containing one object </summary>
		/// <param name="obj"> object to be added to the SET. </param>
		public ASN1Set(ASN1Encodable obj)
		{
			set.addElement(obj);
		}

		/// <summary>
		/// Create a SET containing a vector of objects. </summary>
		/// <param name="v"> a vector of objects to make up the SET. </param>
		/// <param name="doSort"> true if should be sorted DER style, false otherwise. </param>
		public ASN1Set(ASN1EncodableVector v, bool doSort)
		{
			for (int i = 0; i != v.size(); i++)
			{
				set.addElement(v.get(i));
			}

			if (doSort)
			{
				this.sort();
			}
		}

		/// <summary>
		/// Create a SET containing an array of objects. </summary>
		/// <param name="array"> an array of objects to make up the SET. </param>
		/// <param name="doSort"> true if should be sorted DER style, false otherwise. </param>
		public ASN1Set(ASN1Encodable[] array, bool doSort)
		{
			for (int i = 0; i != array.Length; i++)
			{
				set.addElement(array[i]);
			}

			if (doSort)
			{
				this.sort();
			}
		}

		public virtual Enumeration getObjects()
		{
			return set.elements();
		}

		/// <summary>
		/// return the object at the set position indicated by index.
		/// </summary>
		/// <param name="index"> the set number (starting at zero) of the object </param>
		/// <returns> the object at the set position indicated by index. </returns>
		public virtual ASN1Encodable getObjectAt(int index)
		{
			return (ASN1Encodable)set.elementAt(index);
		}

		/// <summary>
		/// return the number of objects in this set.
		/// </summary>
		/// <returns> the number of objects in this set. </returns>
		public virtual int size()
		{
			return set.size();
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

		public virtual ASN1SetParser parser()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final ASN1Set outer = this;
			ASN1Set outer = this;

			return new ASN1SetParserAnonymousInnerClass(this, outer);
		}

		public class ASN1SetParserAnonymousInnerClass : ASN1SetParser
		{
			private readonly ASN1Set outerInstance;

			private ASN1Set outer;

			public ASN1SetParserAnonymousInnerClass(ASN1Set outerInstance, ASN1Set outer)
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

		/// <summary>
		/// Change current SET object to be encoded as <seealso cref="DERSet"/>.
		/// This is part of Distinguished Encoding Rules form serialization.
		/// </summary>
		public override ASN1Primitive toDERObject()
		{
			if (isSorted)
			{
				ASN1Set derSet = new DERSet();

				derSet.set = this.set;

				return derSet;
			}
			else
			{
				Vector v = new Vector();

				for (int i = 0; i != set.size(); i++)
				{
					v.addElement(set.elementAt(i));
				}

				ASN1Set derSet = new DERSet();

				derSet.set = v;

				derSet.sort();

				return derSet;
			}
		}

		/// <summary>
		/// Change current SET object to be encoded as <seealso cref="DLSet"/>.
		/// This is part of Direct Length form serialization.
		/// </summary>
		public override ASN1Primitive toDLObject()
		{
			ASN1Set derSet = new DLSet();

			derSet.set = this.set;

			return derSet;
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1Set))
			{
				return false;
			}

			ASN1Set other = (ASN1Set)o;

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

			// unfortunately null was allowed as a substitute for DER null
			if (encObj == null)
			{
				return DERNull.INSTANCE;
			}

			return encObj;
		}

		/// <summary>
		/// return true if a <= b (arrays are assumed padded with zeros).
		/// </summary>
		private bool lessThanOrEqual(byte[] a, byte[] b)
		{
			int len = Math.Min(a.Length, b.Length);
			for (int i = 0; i != len; ++i)
			{
				if (a[i] != b[i])
				{
					return (a[i] & 0xff) < (b[i] & 0xff);
				}
			}
			return len == a.Length;
		}

		private byte[] getDEREncoded(ASN1Encodable obj)
		{
			try
			{
				return obj.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("cannot encode object added to SET");
			}
		}

		public virtual void sort()
		{
			if (!isSorted)
			{
				isSorted = true;
				if (set.size() > 1)
				{
					bool swapped = true;
					int lastSwap = set.size() - 1;

					while (swapped)
					{
						int index = 0;
						int swapIndex = 0;
						byte[] a = getDEREncoded((ASN1Encodable)set.elementAt(0));

						swapped = false;

						while (index != lastSwap)
						{
							byte[] b = getDEREncoded((ASN1Encodable)set.elementAt(index + 1));

							if (lessThanOrEqual(a, b))
							{
								a = b;
							}
							else
							{
								object o = set.elementAt(index);

								set.setElementAt(set.elementAt(index + 1), index);
								set.setElementAt(o, index + 1);

								swapped = true;
								swapIndex = index;
							}

							index++;
						}

						lastSwap = swapIndex;
					}
				}
			}
		}

		public override bool isConstructed()
		{
			return true;
		}

		public override abstract void encode(ASN1OutputStream @out);

		public override string ToString()
		{
			return set.ToString();
		}

		public virtual Iterator<ASN1Encodable> iterator()
		{
			return new Arrays.Iterator<ASN1Encodable>(toArray());
		}
	}

}