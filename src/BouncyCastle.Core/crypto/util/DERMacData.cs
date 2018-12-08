using org.bouncycastle.crypto.util;

using System.Collections.Generic;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.util
{
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Builder and holder class for preparing SP 800-56A compliant MacData. Elements in the data are encoded
	/// as DER objects with empty octet strings used to represent nulls in compulsory fields.
	/// </summary>
	public sealed class DERMacData
	{
		public sealed class Type
		{
			public static readonly Type UNILATERALU = new Type("UNILATERALU", InnerEnum.UNILATERALU, "KC_1_U");
			public static readonly Type UNILATERALV = new Type("UNILATERALV", InnerEnum.UNILATERALV, "KC_1_V");
			public static readonly Type BILATERALU = new Type("BILATERALU", InnerEnum.BILATERALU, "KC_2_U");
			public static readonly Type BILATERALV = new Type("BILATERALV", InnerEnum.BILATERALV, "KC_2_V");

			private static readonly IList<Type> valueList = new List<Type>();

			static Type()
			{
				valueList.Add(UNILATERALU);
				valueList.Add(UNILATERALV);
				valueList.Add(BILATERALU);
				valueList.Add(BILATERALV);
			}

			public enum InnerEnum
			{
				UNILATERALU,
				UNILATERALV,
				BILATERALU,
				BILATERALV
			}

			public readonly InnerEnum innerEnumValue;
			private readonly string nameValue;
			private readonly int ordinalValue;
			private static int nextOrdinal = 0;

			internal readonly string enc;

			public Type(string name, InnerEnum innerEnum, string enc)
			{
				this.enc = enc;

				nameValue = name;
				ordinalValue = nextOrdinal++;
				innerEnumValue = innerEnum;
			}

			public byte[] getHeader()
			{
				return Strings.toByteArray(enc);
			}

			public static IList<Type> values()
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

			public static Type valueOf(string name)
			{
				foreach (Type enumInstance in Type.valueList)
				{
					if (enumInstance.nameValue == name)
					{
						return enumInstance;
					}
				}
				throw new System.ArgumentException(name);
			}
		}

		/// <summary>
		/// Builder to create OtherInfo
		/// </summary>
		public sealed class Builder
		{
			internal readonly Type type;

			internal ASN1OctetString idU;
			internal ASN1OctetString idV;
			internal ASN1OctetString ephemDataU;
			internal ASN1OctetString ephemDataV;
			internal byte[] text;

			/// <summary>
			/// Create a basic builder with just the compulsory fields.
			/// </summary>
			/// <param name="type"> the MAC header </param>
			/// <param name="idU">  sender party ID. </param>
			/// <param name="idV">  receiver party ID. </param>
			/// <param name="ephemDataU"> ephemeral data from sender. </param>
			/// <param name="ephemDataV"> ephemeral data from receiver. </param>
			public Builder(Type type, byte[] idU, byte[] idV, byte[] ephemDataU, byte[] ephemDataV)
			{
				this.type = type;
				this.idU = DerUtil.getOctetString(idU);
				this.idV = DerUtil.getOctetString(idV);
				this.ephemDataU = DerUtil.getOctetString(ephemDataU);
				this.ephemDataV = DerUtil.getOctetString(ephemDataV);
			}

			/// <summary>
			/// Add optional text.
			/// </summary>
			/// <param name="text"> optional agreed text to add to the MAC. </param>
			/// <returns> the current builder instance. </returns>
			public Builder withText(byte[] text)
			{
				this.text = DerUtil.toByteArray(new DERTaggedObject(false, 0, DerUtil.getOctetString(text)));

				return this;
			}

			public DERMacData build()
			{
				switch (type.innerEnumValue)
				{
				case DERMacData.Type.InnerEnum.UNILATERALU:
				case DERMacData.Type.InnerEnum.BILATERALU:
					return new DERMacData(concatenate(type.getHeader(), DerUtil.toByteArray(idU), DerUtil.toByteArray(idV), DerUtil.toByteArray(ephemDataU), DerUtil.toByteArray(ephemDataV), text));
				case DERMacData.Type.InnerEnum.UNILATERALV:
				case DERMacData.Type.InnerEnum.BILATERALV:
					return new DERMacData(concatenate(type.getHeader(), DerUtil.toByteArray(idV), DerUtil.toByteArray(idU), DerUtil.toByteArray(ephemDataV), DerUtil.toByteArray(ephemDataU), text));
				}

				throw new IllegalStateException("Unknown type encountered in build"); // should never happen
			}

			public byte[] concatenate(byte[] header, byte[] id1, byte[] id2, byte[] ed1, byte[] ed2, byte[] text)
			{
				return Arrays.concatenate(Arrays.concatenate(header, id1, id2), Arrays.concatenate(ed1, ed2, text));
			}
		}

		private readonly byte[] macData;

		private DERMacData(byte[] macData)
		{
			this.macData = macData;
		}

		public byte[] getMacData()
		{
			return Arrays.clone(macData);
		}
	}

}