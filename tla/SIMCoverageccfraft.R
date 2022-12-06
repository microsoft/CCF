require(ggplot2)
require(dplyr)

df <- unique(read.csv(header = TRUE, sep = "#", file = "./SIMCoverageccfraft_S5.csv"))

# Add a column to df that combines the three columns Spec, P, and C.
df$SpecP <- paste(df$Spec, df$P, df$Q, df$R, sep = "_")

# Eyeball if all configurations are roughly equally represented.
df %>% group_by(SpecP) %>% summarize(count = n())

# Print configurations where leaders retire.
df %>% 
  group_by(SpecP, state) %>% 
  summarize(count = n()) %>% 
  filter(state == "RetiredLeader")

# Count the occurrences of each character sequence in column state
# grouped by column SpecP.
df %>%
  group_by(SpecP, state) %>%
  summarize(count = n()) %>%
  ggplot(aes(x=SpecP, fill=state, y=count)) +
    geom_bar(stat="identity") +
    theme(axis.text.x = element_text(angle = 90, vjust = 0.5, hjust=1))

