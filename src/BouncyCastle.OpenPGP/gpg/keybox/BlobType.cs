using System.Collections.Generic;

namespace org.bouncycastle.gpg.keybox
{
	public sealed class BlobType
	{
		public static readonly BlobType EMPTY_BLOB = new BlobType("EMPTY_BLOB", InnerEnum.EMPTY_BLOB, 0);
		public static readonly BlobType FIRST_BLOB = new BlobType("FIRST_BLOB", InnerEnum.FIRST_BLOB, 1);
		public static readonly BlobType OPEN_PGP_BLOB = new BlobType("OPEN_PGP_BLOB", InnerEnum.OPEN_PGP_BLOB, 2);
		public static readonly BlobType X509_BLOB = new BlobType("X509_BLOB", InnerEnum.X509_BLOB, 3);

		private static readonly IList<BlobType> valueList = new List<BlobType>();

		static BlobType()
		{
			valueList.Add(EMPTY_BLOB);
			valueList.Add(FIRST_BLOB);
			valueList.Add(OPEN_PGP_BLOB);
			valueList.Add(X509_BLOB);
		}

		public enum InnerEnum
		{
			EMPTY_BLOB,
			FIRST_BLOB,
			OPEN_PGP_BLOB,
			X509_BLOB
		}

		public readonly InnerEnum innerEnumValue;
		private readonly string nameValue;
		private readonly int ordinalValue;
		private static int nextOrdinal = 0;

		private readonly int byteValue;

		public BlobType(string name, InnerEnum innerEnum, int byteValue)
		{
			this.byteValue = byteValue;

			nameValue = name;
			ordinalValue = nextOrdinal++;
			innerEnumValue = innerEnum;
		}

		public static BlobType fromByte(int byteVal)
		{
			foreach (BlobType blobType in BlobType.values())
			{
				if (blobType.byteValue == byteVal)
				{
					return blobType;
				}
			}
			throw new IllegalArgumentException("Unknown blob type " + byteVal.ToString("x"));
		}

		public int getByteValue()
		{
			return byteValue;
		}


		public static IList<BlobType> values()
		{
			return valueList;
		}

		public int ordinal()
		{
			return ordinalValue;
		}

		public override string ToString()
		{
			return nameValue;
		}

		public static BlobType valueOf(string name)
		{
			foreach (BlobType enumInstance in BlobType.valueList)
			{
				if (enumInstance.nameValue == name)
				{
					return enumInstance;
				}
			}
			throw new System.ArgumentException(name);
		}
	}

}