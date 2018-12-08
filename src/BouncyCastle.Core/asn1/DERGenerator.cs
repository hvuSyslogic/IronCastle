using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Basic class for streaming DER encoding generators.
	/// </summary>
	public abstract class DERGenerator : ASN1Generator
	{
		private bool _tagged = false;
		private bool _isExplicit;
		private int _tagNo;

		public DERGenerator(OutputStream @out) : base(@out)
		{
		}

		/// <summary>
		/// Create a DER encoding generator for a tagged object.
		/// </summary>
		/// <param name="out"> the output stream to encode objects to. </param>
		/// <param name="tagNo"> the tag number to head the output stream with. </param>
		/// <param name="isExplicit"> true if the tagging should be explicit, false otherwise. </param>
		public DERGenerator(OutputStream @out, int tagNo, bool isExplicit) : base(@out)
		{

			_tagged = true;
			_isExplicit = isExplicit;
			_tagNo = tagNo;
		}

		private void writeLength(OutputStream @out, int length)
		{
			if (length > 127)
			{
				int size = 1;
				int val = length;

				while ((val = (int)((uint)val >> 8)) != 0)
				{
					size++;
				}

				@out.write(unchecked((byte)(size | 0x80)));

				for (int i = (size - 1) * 8; i >= 0; i -= 8)
				{
					@out.write((byte)(length >> i));
				}
			}
			else
			{
				@out.write((byte)length);
			}
		}

		public virtual void writeDEREncoded(OutputStream @out, int tag, byte[] bytes)
		{
			@out.write(tag);
			writeLength(@out, bytes.Length);
			@out.write(bytes);
		}

		public virtual void writeDEREncoded(int tag, byte[] bytes)
		{
			if (_tagged)
			{
				int tagNum = _tagNo | BERTags_Fields.TAGGED;

				if (_isExplicit)
				{
					int newTag = _tagNo | BERTags_Fields.CONSTRUCTED | BERTags_Fields.TAGGED;

					ByteArrayOutputStream bOut = new ByteArrayOutputStream();

					writeDEREncoded(bOut, tag, bytes);

					writeDEREncoded(_out, newTag, bOut.toByteArray());
				}
				else
				{
					if ((tag & BERTags_Fields.CONSTRUCTED) != 0)
					{
						writeDEREncoded(_out, tagNum | BERTags_Fields.CONSTRUCTED, bytes);
					}
					else
					{
						writeDEREncoded(_out, tagNum, bytes);
					}
				}
			}
			else
			{
				writeDEREncoded(_out, tag, bytes);
			}
		}
	}

}