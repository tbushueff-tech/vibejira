import java.util.*;
import java.nio.file.*;
import java.lang.reflect.*;
public class ExportJavaZones {
  static String quote(String s) { return "\""+s.replace("\\","\\\\").replace("\"","\\\"")+"\""; }
  static Object field(Object object,String name) throws Exception {
    Field field=object.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(object);
  }
  static String rule(SimpleTimeZone zone,String prefix) throws Exception {
    return "["+((int)field(zone,prefix+"Month")+1)+","+field(zone,prefix+"Day")+","+field(zone,prefix+"DayOfWeek")+","+((int)field(zone,prefix+"Time")/1000)+","+field(zone,prefix+"TimeMode")+","+field(zone,prefix+"Mode")+"]";
  }
  public static void main(String[] args) throws Exception {
    StringBuilder rows=new StringBuilder(); List<String> data=new ArrayList<>(); Map<String,Integer> indices=new HashMap<>();
    for(String id:new TreeSet<>(Arrays.asList(TimeZone.getAvailableIDs()))) {
      TimeZone tz=TimeZone.getTimeZone(id);
      long[] transitions=(long[])field(tz,"transitions");
      int[] offsets=(int[])field(tz,"offsets");
      int raw=(int)field(tz,"rawOffset");
      StringBuilder out=new StringBuilder("{b:[");out.append(raw/1000).append(",0],t:[");
      boolean comma=false;long last=Long.MAX_VALUE;
      if(transitions!=null) for(long transition:transitions) {
        long millis=transition>>12;last=millis;
        if(comma)out.append(',');comma=true;
        out.append('[').append(millis/1000).append(',').append(offsets[(int)(transition&15)]/1000).append(',').append((transition&240)!=0?1:0).append(']');
      }
      out.append("],c:").append(last==Long.MAX_VALUE?"null":Long.toString(last/1000)).append(",r:");
      Method method=tz.getClass().getDeclaredMethod("getLastRuleInstance");method.setAccessible(true);
      SimpleTimeZone lastRule=(SimpleTimeZone)method.invoke(tz);
      if(lastRule==null)out.append("null");
      else out.append("{o:").append(lastRule.getRawOffset()/1000).append(",d:").append(lastRule.getDSTSavings()/1000).append(",s:").append(rule(lastRule,"start")).append(",e:").append(rule(lastRule,"end")).append('}');
      out.append("}"); String value=out.toString(); Integer index=indices.get(value); if(index==null){index=data.size();indices.put(value,index);data.add(value);}
      rows.append("[").append(quote(id)).append(",[").append(quote(tz.getDisplayName(false,TimeZone.SHORT,Locale.US))).append(',').append(quote(tz.getDisplayName(true,TimeZone.SHORT,Locale.US))).append("],").append(index).append("],\n");
    }
    String output="// Generated from Java 22.0.2 legacy TimeZone tables; regenerate with v2/java/ExportJavaZones.java.\nconst ruleSets=[\n"+String.join(",\n",data)+"\n];\nconst zones=[\n"+rows+"];\nexport const javaTimeZones=Object.fromEntries(zones.map(([id,n,index])=>[id,{n,...ruleSets[index]}]));\n"; Files.writeString(Path.of(args[0]),output);
  }
}
