namespace org.bouncycastle.bcpg.sig
{

	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Class provided a NotationData object according to
	/// RFC2440, Chapter 5.2.3.15. Notation Data
	/// </summary>
	public class NotationData : SignatureSubpacket
	{
		public const int HEADER_FLAG_LENGTH = 4;
		public const int HEADER_NAME_LENGTH = 2;
		public const int HEADER_VALUE_LENGTH = 2;

		public NotationData(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.NOTATION_DATA, critical, isLongLength, data)
		{
		}

		public NotationData(bool critical, bool humanReadable, string notationName, string notationValue) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.NOTATION_DATA, critical, false, createData(humanReadable, notationName, notationValue))
		{
		}

		private static byte[] createData(bool humanReadable, string notationName, string notationValue)
		{
			ByteArrayOutputStream @out = new ByteArrayOutputStream();

	//        (4 octets of flags, 2 octets of name length (M),
	//        2 octets of value length (N),
	//        M octets of name data,
	//        N octets of value data)

			// flags
			@out.write(humanReadable ? 0x80 : 0x00);
			@out.write(0x0);
			@out.write(0x0);
			@out.write(0x0);

			byte[] nameData, valueData = null;
			int nameLength, valueLength;

			nameData = Strings.toUTF8ByteArray(notationName);
			nameLength = Math.Min(nameData.Length, 0xFFFF);

			if (nameLength != nameData.Length)
			{
				throw new IllegalArgumentException("notationName exceeds maximum length.");
			}

			valueData = Strings.toUTF8ByteArray(notationValue);
			valueLength = Math.Min(valueData.Length, 0xFFFF);
			if (valueLength != valueData.Length)
			{
				throw new IllegalArgumentException("notationValue exceeds maximum length.");
			}

			// name length
			@out.write(((int)((uint)nameLength >> 8)) & 0xFF);
			@out.write(((int)((uint)nameLength >> 0)) & 0xFF);

			// value length
			@out.write(((int)((uint)valueLength >> 8)) & 0xFF);
			@out.write(((int)((uint)valueLength >> 0)) & 0xFF);

			// name
			@out.write(nameData, 0, nameLength);

			// value
			@out.write(valueData, 0, valueLength);

			return @out.toByteArray();
		}

		public virtual bool isHumanReadable()
		{
			return data[0] == unchecked((byte)0x80);
		}

		public virtual string getNotationName()
		{
			int nameLength = (((data[HEADER_FLAG_LENGTH] & 0xff) << 8) + (data[HEADER_FLAG_LENGTH + 1] & 0xff));

			byte[] bName = new byte[nameLength];
			JavaSystem.arraycopy(data, HEADER_FLAG_LENGTH + HEADER_NAME_LENGTH + HEADER_VALUE_LENGTH, bName, 0, nameLength);

			return Strings.fromUTF8ByteArray(bName);
		}

		public virtual string getNotationValue()
		{
			return Strings.fromUTF8ByteArray(getNotationValueBytes());
		}

		public virtual byte[] getNotationValueBytes()
		{
			int nameLength = (((data[HEADER_FLAG_LENGTH] & 0xff) << 8) + (data[HEADER_FLAG_LENGTH + 1] & 0xff));
			int valueLength = (((data[HEADER_FLAG_LENGTH + HEADER_NAME_LENGTH] & 0xff) << 8) + (data[HEADER_FLAG_LENGTH + HEADER_NAME_LENGTH + 1] & 0xff));

			byte[] bValue = new byte[valueLength];
			JavaSystem.arraycopy(data, HEADER_FLAG_LENGTH + HEADER_NAME_LENGTH + HEADER_VALUE_LENGTH + nameLength, bValue, 0, valueLength);
			return bValue;
		}
	}

}