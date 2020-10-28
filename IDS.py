#!/usr/bin/env python
# coding: utf-8

# # ARP-SPOOFING

# In[96]:


import warnings
warnings.filterwarnings("ignore")

import numpy as np 
import pandas as pd
df1=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//mitm-arpspoofing-1.csv")
df2=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//mitm-arpspoofing-2.csv")
df3=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//mitm-arpspoofing-3.csv")
df4=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//mitm-arpspoofing-4.csv")
df5=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//mitm-arpspoofing-5.csv")
df6=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//mitm-arpspoofing-6.csv")
print(df1.describe())
print(df2.describe())
print(df3.describe())
print(df4.describe())
print(df5.describe())
print(df6.describe())


# In[97]:


df1['Anomaly']=''
df2['Anomaly']=''
df3['Anomaly']=''
df4['Anomaly']=''
df5['Anomaly']=''
df6['Anomaly']=''


# In[98]:


df1.head(200)


# ### filtering for mitm-arpspoofing-1

# In[124]:


count1=0
for i in range(len(df1)):
    if ((((df1['Source'][i] == '192.168.0.16' and df1['Destination'][i] == '192.168.0.13') or (df1['Source'][i] == '192.168.0.13' and df1['Destination'][i] == '192.168.0.16')) and df1['Protocol'][i]!='ICMP' and df1['Protocol'][i]=='TCP') or (df1['Source'][i] == 'f0:18:98:5e:ff:9f' and (df1['Destination'][i] == 'bc:1c:81:4b:ae:ba' or df1['Destination'][i] == '48:4b:aa:2c:d8:f9'))):
        df1['Anomaly'][i]='Yes-arp_spoofing'
        count1 +=1
    else:
        df1['Anomaly'][i]='No'
        #print(False)
print(count1)   


# ### filtering for mitm-arpspoofing-2

# In[125]:


count2=0
for i in range(len(df2)):
    if ((((df2['Source'][i] == '192.168.0.16' and df2['Destination'][i] == '192.168.0.13') or (df2['Source'][i] == '192.168.0.13' and df2['Destination'][i] == '192.168.0.16')) and df2['Protocol'][i]!='ICMP' and df2['Protocol'][i]=='TCP') or (df2['Source'][i] == 'f0:18:98:5e:ff:9f' and (df2['Destination'][i] == 'bc:1c:81:4b:ae:ba' or df2['Destination'][i] == '48:4b:aa:2c:d8:f9'))):
        df2['Anomaly'][i]='Yes-arp_spoofing'    
        count2 +=1
    else:
        df2['Anomaly'][i]='No'
print(count2)  


# ### filtering for mitm-arpspoofing-3

# In[126]:


count3=0
for i in range(len(df3)):
    if ((((df3['Source'][i] == '192.168.0.16' and df3['Destination'][i] == '192.168.0.13') or (df3['Source'][i] == '192.168.0.13' and df3['Destination'][i] == '192.168.0.16')) and df3['Protocol'][i]!='ICMP' and df3['Protocol'][i]=='TCP') or (df3['Source'][i] == 'f0:18:98:5e:ff:9f' and (df3['Destination'][i] == 'bc:1c:81:4b:ae:ba' or df3['Destination'][i] == '48:4b:aa:2c:d8:f9'))):
        df3['Anomaly'][i]='Yes-arp_spoofing'
        count3 +=1
    else:
        df3['Anomaly'][i]='No'
print(count3)  


# ### filtering for mitm-arpspoofing-4 

# In[127]:


count4=0
for i in range(len(df4)):
    if ((df4['Source'][i] == '192.168.0.24' or df4['Destination'][i]== '192.168.0.24') and df4['Protocol'][i]!='ICMP' and df4['Protocol'][i]=='TCP') or (df4['Source'][i]== 'f0:18:98:5e:ff:9f' and (df4['Destination'][i] == '04:32:f4:45:17:b3' or df4['Destination'][i] == '88:36:6c:d7:1c:56')):
        df4['Anomaly'][i]='Yes-arp_spoofing'
        count4 +=1
    else:
        df4['Anomaly'][i]='No'
print(count4) 


# ### filtering for mitm-arpspoofing-5

# In[128]:


count5=0
for i in range(len(df5)):
    if (((df5['Source'][i]== '192.168.0.24' or df5['Destination'][i]== '192.168.0.24') and df5['Protocol'][i]!='ICMP' and df5['Protocol'][i]=='TCP') or (df5['Source'][i] == 'f0:18:98:5e:ff:9f' and (df5['Destination'][i] == '04:32:f4:45:17:b3' or df5['Destination'][i] == '88:36:6c:d7:1c:56'))):
        df5['Anomaly'][i]='Yes-arp_spoofing'
        count5 +=1
    else:
        df5['Anomaly'][i]='No'
print(count5)


# ### filtering for mitm-arpspoofing-6

# In[129]:


count6=0
for i in range(len(df6)):
    if (((df6['Source'][i]== '192.168.0.24' or df6['Destination'][i]== '192.168.0.24') and df6['Protocol'][i]!='ICMP' and df6['Protocol'][i]=='TCP') or (df6['Source'][i] == 'f0:18:98:5e:ff:9f' and (df6['Destination'][i] == '04:32:f4:45:17:b3' or df6['Destination'][i] == '88:36:6c:d7:1c:56'))):
        df6['Anomaly'][i]='Yes-arp_spoofing'
        count6 +=1
    else:
        df6['Anomaly'][i]='No'
print(count6) 


# In[105]:


df1.head(2)


# In[106]:


df2.head(2)


# In[123]:


df3.head(2)


# #### concatenating the dataframes into one

# In[137]:


df_arp=pd.concat([df1,df2,df3,df4,df5,df6])


# In[138]:


df_arp.head()


# In[139]:


df_arp.describe()


# # SYN-FLOODING

# In[107]:


df11=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//dos-synflooding-1.csv")
df12=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//dos-synflooding-2.csv")
df13=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//dos-synflooding-3.csv")
df14=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//dos-synflooding-4.csv")
df15=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//dos-synflooding-5.csv")
df16=pd.read_csv("C://Users//Harsh//Documents//PE_JYOTSANA_MA'AM//Packets//dos-synflooding-6.csv")
print(df11.describe())
print(df12.describe())
print(df13.describe())
print(df14.describe())
print(df15.describe())
print(df16.describe())


# In[108]:


df11['Anomaly']=''
df12['Anomaly']=''
df13['Anomaly']=''
df14['Anomaly']=''
df15['Anomaly']=''
df16['Anomaly']=''


# In[109]:


df11.head()


# In[110]:


df11['Info'][5000]


# In[111]:


if '554' and 'SYN' in df11['Info'][5000]:
    print(True)


# In[112]:


df11['Source'][1][:3]


# ### filtering for dos_syn-flooding-1

# In[130]:


cnt1=0
for i in range(len(df11)):
    if df11['Source'][i][:3]=='222' and df11['Destination'][i]=='192.168.0.13' and df11['Protocol'][i]=='TCP' and ('554' and 'SYN' in df11['Info'][i]):
        cnt1 +=1
        df11['Anomaly'][i]='Yes-syn_flooding'
    else:
        df11['Anomaly'][i]='No'
print(cnt1) 


# In[131]:


df11.head()


# In[132]:


cnt2=0
for i in range(len(df12)):
    if df12['Source'][i][:3]=='222' and df12['Destination'][i]=='192.168.0.13' and df12['Protocol'][i]=='TCP' and ('554' and 'SYN' in df12['Info'][i]):
        cnt2 +=1
        df12['Anomaly'][i]='Yes-syn_flooding'
    else:
        df12['Anomaly'][i]='No'
print(cnt2) 


# In[133]:


cnt3=0
for i in range(len(df13)):
    if df13['Source'][i][:3]=='111' and df13['Destination'][i]=='192.168.0.13' and df13['Protocol'][i]=='TCP' and ('554' and 'SYN' in df13['Info'][i]):
        cnt3 +=1
        df13['Anomaly'][i]='Yes-syn_flooding'
    else:
        df13['Anomaly'][i]='No'
print(cnt3) 


# In[134]:


cnt4=0
for i in range(len(df14)):
    if df14['Source'][i][:3]=='111' and df14['Destination'][i]=='192.168.0.24' and df14['Protocol'][i]=='TCP' and ('19604' and 'SYN' in df14['Info'][i]):
        cnt4 +=1
        df14['Anomaly'][i]='Yes-syn_flooding'
    else:
        df14['Anomaly'][i]='No'
print(cnt4) 


# In[135]:


cnt5=0
for i in range(len(df15)):
    if df15['Source'][i][:3]=='111' and df15['Destination'][i]=='192.168.0.24' and df15['Protocol'][i]=='TCP' and ('19604' and 'SYN' in df15['Info'][i]):
        cnt5 +=1
        df15['Anomaly'][i]='Yes-syn_flooding'
    else:
        df15['Anomaly'][i]='No'
print(cnt5) 


# In[136]:


cnt6=0
for i in range(len(df16)):
    if df16['Source'][i][:3]=='111' and df16['Destination'][i]=='192.168.0.24' and df16['Protocol'][i]=='TCP' and ('19604' and 'SYN' in df16['Info'][i]):
        cnt6 +=1
        df16['Anomaly'][i]='Yes-syn_flooding'
    else:
        df16['Anomaly'][i]='No'
print(cnt6) 


# In[120]:


df11.head(2)


# In[121]:


df12.head(2)


# In[122]:


df13.head(2)


# #### concatenating the dataframes into one 

# In[140]:


df_syn=pd.concat([df11,df12,df13,df14,df15,df16])


# In[141]:


df_syn.head()


# In[142]:


df_syn.describe()


# #### concatenating df_arp and df_syn

# In[143]:


df=pd.concat([df_syn,df_arp])


# In[144]:


df.head()


# In[145]:


df.describe()

