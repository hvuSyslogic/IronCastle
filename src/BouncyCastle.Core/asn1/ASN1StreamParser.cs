using System.IO;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A parser for ASN.1 streams which also returns, where possible, parsers for the objects it encounters.
	/// </summary>
	public class ASN1StreamParser
	{
		private readonly InputStream _in;
		private readonly int _limit;
		private readonly byte[][] tmpBuffers;

		public ASN1StreamParser(InputStream @in) : this(@in, StreamUtil.findLimit(@in))
		{
		}

		public ASN1StreamParser(InputStream @in, int limit)
		{
			this._in = @in;
			this._limit = limit;

			this.tmpBuffers = new byte[11][];
		}

		public ASN1StreamParser(byte[] encoding) : this(new ByteArrayInputStream(encoding), encoding.Length)
		{
		}

		public virtual ASN1Encodable readIndef(int tagValue)
		{
			// Note: INDEF => CONSTRUCTED

			// TODO There are other tags that may be constructed (e.g. BIT_STRING)
			switch (tagValue)
			{
				case BERTags_Fields.EXTERNAL:
					return new DERExternalParser(this);
				case BERTags_Fields.OCTET_STRING:
					return new BEROctetStringParser(this);
				case BERTags_Fields.SEQUENCE:
					return new BERSequenceParser(this);
				case BERTags_Fields.SET:
					return new BERSetParser(this);
				default:
					throw new ASN1Exception("unknown BER object encountered: 0x" + tagValue.ToString("x"));
			}
		}

		public virtual ASN1Encodable readImplicit(bool constructed, int tag)
		{
			if (_in is IndefiniteLengthInputStream)
			{
				if (!constructed)
				{
					throw new IOException("indefinite-length primitive encoding encountered");
				}

				return readIndef(tag);
			}

			if (constructed)
			{
				switch (tag)
				{
					case BERTags_Fields.SET:
						return new DERSetParser(this);
					case BERTags_Fields.SEQUENCE:
						return new DERSequenceParser(this);
					case BERTags_Fields.OCTET_STRING:
						return new BEROctetStringParser(this);
				}
			}
			else
			{
				switch (tag)
				{
					case BERTags_Fields.SET:
						throw new ASN1Exception("sequences must use constructed encoding (see X.690 8.9.1/8.10.1)");
					case BERTags_Fields.SEQUENCE:
						throw new ASN1Exception("sets must use constructed encoding (see X.690 8.11.1/8.12.1)");
					case BERTags_Fields.OCTET_STRING:
						return new DEROctetStringParser((DefiniteLengthInputStream)_in);
				}
			}

			throw new ASN1Exception("implicit tagging not implemented");
		}

		public virtual ASN1Primitive readTaggedObject(bool constructed, int tag)
		{
			if (!constructed)
			{
				// Note: !CONSTRUCTED => IMPLICIT
				DefiniteLengthInputStream defIn = (DefiniteLengthInputStream)_in;
				return new DERTaggedObject(false, tag, new DEROctetString(defIn.toByteArray()));
			}

			ASN1EncodableVector v = readVector();

			if (_in is IndefiniteLengthInputStream)
			{
				return v.size() == 1 ? new BERTaggedObject(true, tag, v.get(0)) : new BERTaggedObject(false, tag, BERFactory.createSequence(v));
			}

			return v.size() == 1 ? new DERTaggedObject(true, tag, v.get(0)) : new DERTaggedObject(false, tag, DERFactory.createSequence(v));
		}

		public virtual ASN1Encodable readObject()
		{
			int tag = _in.read();
			if (tag == -1)
			{
				return null;
			}

			//
			// turn of looking for "00" while we resolve the tag
			//
			set00Check(false);

			//
			// calculate tag number
			//
			int tagNo = ASN1InputStream.readTagNumber(_in, tag);

			bool isConstructed = (tag & BERTags_Fields.CONSTRUCTED) != 0;

			//
			// calculate length
			//
			int length = ASN1InputStream.readLength(_in, _limit);

			if (length < 0) // indefinite-length method
			{
				if (!isConstructed)
				{
					throw new IOException("indefinite-length primitive encoding encountered");
				}

				IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(_in, _limit);
				ASN1StreamParser sp = new ASN1StreamParser(indIn, _limit);

				if ((tag & BERTags_Fields.APPLICATION) != 0)
				{
					return new BERApplicationSpecificParser(tagNo, sp);
				}

				if ((tag & BERTags_Fields.TAGGED) != 0)
				{
					return new BERTaggedObjectParser(true, tagNo, sp);
				}

				return sp.readIndef(tagNo);
			}
			else
			{
				DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(_in, length);

				if ((tag & BERTags_Fields.APPLICATION) != 0)
				{
					return new DLApplicationSpecific(isConstructed, tagNo, defIn.toByteArray());
				}

				if ((tag & BERTags_Fields.TAGGED) != 0)
				{
					return new BERTaggedObjectParser(isConstructed, tagNo, new ASN1StreamParser(defIn));
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
							return new BEROctetStringParser(new ASN1StreamParser(defIn));
						case BERTags_Fields.SEQUENCE:
							return new DERSequenceParser(new ASN1StreamParser(defIn));
						case BERTags_Fields.SET:
							return new DERSetParser(new ASN1StreamParser(defIn));
						case BERTags_Fields.EXTERNAL:
							return new DERExternalParser(new ASN1StreamParser(defIn));
						default:
							throw new IOException("unknown tag " + tagNo + " encountered");
					}
				}

				// Some primitive encodings can be handled by parsers too...
				switch (tagNo)
				{
					case BERTags_Fields.OCTET_STRING:
						return new DEROctetStringParser(defIn);
				}

				try
				{
					return ASN1InputStream.createPrimitiveDERObject(tagNo, defIn, tmpBuffers);
				}
				catch (IllegalArgumentException e)
				{
					throw new ASN1Exception("corrupted stream detected", e);
				}
			}
		}

		private void set00Check(bool enabled)
		{
			if (_in is IndefiniteLengthInputStream)
			{
				((IndefiniteLengthInputStream)_in).setEofOn00(enabled);
			}
		}

		public virtual ASN1EncodableVector readVector()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			ASN1Encodable obj;
			while ((obj = readObject()) != null)
			{
				if (obj is InMemoryRepresentable)
				{
					v.add(((InMemoryRepresentable)obj).getLoadedObject());
				}
				else
				{
					v.add(obj.toASN1Primitive());
				}
			}

			return v;
		}
	}

}