namespace org.bouncycastle.kmip.wire
{
	public class KMIPType
	{
		private KMIPType()
		{

		}

		public const int STRUCTURE = 0x01;
		public const int INTEGER = 0x02;
		public const int LONG_INTEGER = 0x03;
		public const int BIG_INTEGER = 0x04;
		public const int ENUMERATION = 0x05;
		public const int BOOLEAN = 0x06;
		public const int TEXT_STRING = 0x07;
		public const int BYTE_STRING = 0x08;
		public const int DATE_TIME = 0x09;
		public const int INTERVAL = 0x0A;
	}

}