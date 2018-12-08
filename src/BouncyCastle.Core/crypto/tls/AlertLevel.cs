namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 5246 7.2
	/// </summary>
	public class AlertLevel
	{
		public const short warning = 1;
		public const short fatal = 2;

		public static string getName(short alertDescription)
		{
			switch (alertDescription)
			{
			case warning:
				return "warning";
			case fatal:
				return "fatal";
			default:
				return "UNKNOWN";
			}
		}

		public static string getText(short alertDescription)
		{
			return getName(alertDescription) + "(" + alertDescription + ")";
		}
	}

}