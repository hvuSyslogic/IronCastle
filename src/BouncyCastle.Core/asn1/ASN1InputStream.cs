using System.IO;
using org.bouncycastle.notexisting;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util.io;

namespace org.bouncycastle.asn1
{

	
	/// <summary>
	/// A general purpose ASN.1 decoder - note: this class differs from the
	/// others in that it returns null after it has read the last object in
	/// the stream. If an ASN.1 NULL is encountered a DER/BER Null object is
	/// returned.
	/// </summary>
	public class ASN1InputStream : FilterInputStream, BERTags
	{
		private readonly int limit;
		private readonly bool lazyEvaluate;

		private readonly byte[][] tmpBuffers;

		public ASN1InputStream(InputStream @is) : this(@is, StreamUtil.findLimit(@is))
		{
		}

		/// <summary>
		/// Create an ASN1InputStream based on the input byte array. The length of DER objects in
		/// the stream is automatically limited to the length of the input array.
		/// </summary>
		/// <param name="input"> array containing ASN.1 encoded data. </param>
		public ASN1InputStream(byte[] input) : this(new ByteArrayInputStream(input), input.Length)
		{
		}

		/// <summary>
		/// Create an ASN1InputStream based on the input byte array. The length of DER objects in
		/// the stream is automatically limited to the length of the input array.
		/// </summary>
		/// <param name="input"> array containing ASN.1 encoded data. </param>
		/// <param name="lazyEvaluate"> true if parsing inside constructed objects can be delayed. </param>
		public ASN1InputStream(byte[] input, bool lazyEvaluate) : this(new ByteArrayInputStream(input), input.Length, lazyEvaluate)
		{
		}

		/// <summary>
		/// Create an ASN1InputStream where no DER object will be longer than limit.
		/// </summary>
		/// <param name="input"> stream containing ASN.1 encoded data. </param>
		/// <param name="limit"> maximum size of a DER encoded object. </param>
		public ASN1InputStream(InputStream input, int limit) : this(input, limit, false)
		{
		}

		/// <summary>
		/// Create an ASN1InputStream where no DER object will be longer than limit, and constructed
		/// objects such as sequences will be parsed lazily.
		/// </summary>
		/// <param name="input"> stream containing ASN.1 encoded data. </param>
		/// <param name="lazyEvaluate"> true if parsing inside constructed objects can be delayed. </param>
		public ASN1InputStream(InputStream input, bool lazyEvaluate) : this(input, StreamUtil.findLimit(input), lazyEvaluate)
		{
		}

		/// <summary>
		/// Create an ASN1InputStream where no DER object will be longer than limit, and constructed
		/// objects such as sequences will be parsed lazily.
		/// </summary>
		/// <param name="input"> stream containing ASN.1 encoded data. </param>
		/// <param name="limit"> maximum size of a DER encoded object. </param>
		/// <param name="lazyEvaluate"> true if parsing inside constructed objects can be delayed. </param>
		public ASN1InputStream(InputStream input, int limit, bool lazyEvaluate) : base(input)
		{
			this.limit = limit;
			this.lazyEvaluate = lazyEvaluate;
			this.tmpBuffers = new byte[11][];
		}

		public virtual int getLimit()
		{
			return limit;
		}

		public virtual int readLength()
		{
			return readLength(this, limit);
		}

		public virtual void readFully(byte[] bytes)
		{
			if (Streams.readFully(this, bytes) != bytes.Length)
			{
				throw new EOFException("EOF encountered in middle of object");
			}
		}

		/// <summary>
		/// build an object given its tag and the number of bytes to construct it from.
		/// </summary>
		/// <param name="tag"> the full tag details. </param>
		/// <param name="tagNo"> the tagNo defined. </param>
		/// <param name="length"> the length of the object. </param>
		/// <returns> the resulting primitive. </returns>
		/// <exception cref="IOException"> on processing exception. </exception>
		public virtual ASN1Primitive buildObject(int tag, int tagNo, int length)
		{
			bool isConstructed = (tag & BERTags_Fields.CONSTRUCTED) != 0;

			DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(this, length);

			if ((tag & BERTags_Fields.APPLICATION) != 0)
			{
				return new DLApplicationSpecific(isConstructed, tagNo, defIn.toByteArray());
			}

			if ((tag & BERTags_Fields.TAGGED) != 0)
			{
				return (new ASN1StreamParser(defIn)).readTaggedObject(isConstructed, tagNo);
			}

			if (isConstructed)
			{
				// TODO There are other tags that may be constructed (e.g. BIT_STRING)
				switch (tagNo)
				{
					case BERTags_Fields.OCTET_STRING:
						//
						// yes, people actually do this...
						//
						ASN1EncodableVector v = buildDEREncodableVector(defIn);
						ASN1OctetString[] strings = new ASN1OctetString[v.size()];

						for (int i = 0; i != strings.Length; i++)
						{
							strings[i] = (ASN1OctetString)v.get(i);
						}

						return new BEROctetString(strings);
					case BERTags_Fields.SEQUENCE:
						if (lazyEvaluate)
						{
							return new LazyEncodedSequence(defIn.toByteArray());
						}
						else
						{
							return DERFactory.createSequence(buildDEREncodableVector(defIn));
						}
					case BERTags_Fields.SET:
						return DERFactory.createSet(buildDEREncodableVector(defIn));
					case BERTags_Fields.EXTERNAL:
						return new DLExternal(buildDEREncodableVector(defIn));
					default:
						throw new IOException("unknown tag " + tagNo + " encountered");
				}
			}

			return createPrimitiveDERObject(tagNo, defIn, tmpBuffers);
		}

		public virtual ASN1EncodableVector buildEncodableVector()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			ASN1Primitive o;

			while ((o = readObject()) != null)
			{
				v.add(o);
			}

			return v;
		}

		public virtual ASN1EncodableVector buildDEREncodableVector(DefiniteLengthInputStream dIn)
		{
			return (new ASN1InputStream(dIn)).buildEncodableVector();
		}

		public virtual ASN1Primitive readObject()
		{
			int tag = read();
			if (tag <= 0)
			{
				if (tag == 0)
				{
					throw new IOException("unexpected end-of-contents marker");
				}

				return null;
			}

			//
			// calculate tag number
			//
			int tagNo = readTagNumber(this, tag);

			bool isConstructed = (tag & BERTags_Fields.CONSTRUCTED) != 0;

			//
			// calculate length
			//
			int length = readLength();

			if (length < 0) // indefinite-length method
			{
				if (!isConstructed)
				{
					throw new IOException("indefinite-length primitive encoding encountered");
				}

				IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(this, limit);
				ASN1StreamParser sp = new ASN1StreamParser(indIn, limit);

				if ((tag & BERTags_Fields.APPLICATION) != 0)
				{
					return (new BERApplicationSpecificParser(tagNo, sp)).getLoadedObject();
				}

				if ((tag & BERTags_Fields.TAGGED) != 0)
				{
					return (new BERTaggedObjectParser(true, tagNo, sp)).getLoadedObject();
				}

				// TODO There are other tags that may be constructed (e.g. BIT_STRING)
				switch (tagNo)
				{
					case BERTags_Fields.OCTET_STRING:
						return (new BEROctetStringParser(sp)).getLoadedObject();
					case BERTags_Fields.SEQUENCE:
						return (new BERSequenceParser(sp)).getLoadedObject();
					case BERTags_Fields.SET:
						return (new BERSetParser(sp)).getLoadedObject();
					case BERTags_Fields.EXTERNAL:
						return (new DERExternalParser(sp)).getLoadedObject();
					default:
						throw new IOException("unknown BER object encountered");
				}
			}
			else
			{
				try
				{
					return buildObject(tag, tagNo, length);
				}
				catch (IllegalArgumentException e)
				{
					throw new ASN1Exception("corrupted stream detected", e);
				}
			}
		}

		internal static int readTagNumber(InputStream s, int tag)
		{
			int tagNo = tag & 0x1f;

			//
			// with tagged object tag number is bottom 5 bits, or stored at the start of the content
			//
			if (tagNo == 0x1f)
			{
				tagNo = 0;

				int b = s.read();

				// X.690-0207 8.1.2.4.2
				// "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
				if ((b & 0x7f) == 0) // Note: -1 will pass
				{
					throw new IOException("corrupted stream - invalid high tag number found");
				}

				while ((b >= 0) && ((b & 0x80) != 0))
				{
					tagNo |= (b & 0x7f);
					tagNo <<= 7;
					b = s.read();
				}

				if (b < 0)
				{
					throw new EOFException("EOF found inside tag value.");
				}

				tagNo |= (b & 0x7f);
			}

			return tagNo;
		}

		internal static int readLength(InputStream s, int limit)
		{
			int length = s.read();
			if (length < 0)
			{
				throw new EOFException("EOF found when length expected");
			}

			if (length == 0x80)
			{
				return -1; // indefinite-length encoding
			}

			if (length > 127)
			{
				int size = length & 0x7f;

				// Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
				if (size > 4)
				{
					throw new IOException("DER length more than 4 bytes: " + size);
				}

				length = 0;
				for (int i = 0; i < size; i++)
				{
					int next = s.read();

					if (next < 0)
					{
						throw new EOFException("EOF found reading length");
					}

					length = (length << 8) + next;
				}

				if (length < 0)
				{
					throw new IOException("corrupted stream - negative length found");
				}

				if (length >= limit) // after all we must have read at least 1 byte
				{
					throw new IOException("corrupted stream - out of bounds length found");
				}
			}

			return length;
		}

		private static byte[] getBuffer(DefiniteLengthInputStream defIn, byte[][] tmpBuffers)
		{
			int len = defIn.getRemaining();
			if (defIn.getRemaining() < tmpBuffers.Length)
			{
				byte[] buf = tmpBuffers[len];

				if (buf == null)
				{
					buf = tmpBuffers[len] = new byte[len];
				}

				Streams.readFully(defIn, buf);

				return buf;
			}
			else
			{
				return defIn.toByteArray();
			}
		}

		private static char[] getBMPCharBuffer(DefiniteLengthInputStream defIn)
		{
			int len = defIn.getRemaining() / 2;
			char[] buf = new char[len];
			int totalRead = 0;
			while (totalRead < len)
			{
				int ch1 = defIn.read();
				if (ch1 < 0)
				{
					break;
				}
				int ch2 = defIn.read();
				if (ch2 < 0)
				{
					break;
				}
				buf[totalRead++] = (char)((ch1 << 8) | (ch2 & 0xff));
			}

			return buf;
		}

		internal static ASN1Primitive createPrimitiveDERObject(int tagNo, DefiniteLengthInputStream defIn, byte[][] tmpBuffers)
		{
			switch (tagNo)
			{
				case BERTags_Fields.BIT_STRING:
					return ASN1BitString.fromInputStream(defIn.getRemaining(), defIn);
				case BERTags_Fields.BMP_STRING:
					return new DERBMPString(getBMPCharBuffer(defIn));
				case BERTags_Fields.BOOLEAN:
					return ASN1Boolean.fromOctetString(getBuffer(defIn, tmpBuffers));
				case BERTags_Fields.ENUMERATED:
					return ASN1Enumerated.fromOctetString(getBuffer(defIn, tmpBuffers));
				case BERTags_Fields.GENERALIZED_TIME:
					return new ASN1GeneralizedTime(defIn.toByteArray());
				case BERTags_Fields.GENERAL_STRING:
					return new DERGeneralString(defIn.toByteArray());
				case BERTags_Fields.IA5_STRING:
					return new DERIA5String(defIn.toByteArray());
				case BERTags_Fields.INTEGER:
					return new ASN1Integer(defIn.toByteArray(), false);
				case BERTags_Fields.NULL:
					return DERNull.INSTANCE; // actual content is ignored (enforce 0 length?)
				case BERTags_Fields.NUMERIC_STRING:
					return new DERNumericString(defIn.toByteArray());
				case BERTags_Fields.OBJECT_IDENTIFIER:
					return ASN1ObjectIdentifier.fromOctetString(getBuffer(defIn, tmpBuffers));
				case BERTags_Fields.OCTET_STRING:
					return new DEROctetString(defIn.toByteArray());
				case BERTags_Fields.PRINTABLE_STRING:
					return new DERPrintableString(defIn.toByteArray());
				case BERTags_Fields.T61_STRING:
					return new DERT61String(defIn.toByteArray());
				case BERTags_Fields.UNIVERSAL_STRING:
					return new DERUniversalString(defIn.toByteArray());
				case BERTags_Fields.UTC_TIME:
					return new ASN1UTCTime(defIn.toByteArray());
				case BERTags_Fields.UTF8_STRING:
					return new DERUTF8String(defIn.toByteArray());
				case BERTags_Fields.VISIBLE_STRING:
					return new DERVisibleString(defIn.toByteArray());
				case BERTags_Fields.GRAPHIC_STRING:
					return new DERGraphicString(defIn.toByteArray());
				case BERTags_Fields.VIDEOTEX_STRING:
					return new DERVideotexString(defIn.toByteArray());
				default:
					throw new IOException("unknown tag " + tagNo + " encountered");
			}
		}
	}

}